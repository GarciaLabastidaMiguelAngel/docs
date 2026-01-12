package com.tuorg.apigate.gate;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

@Service
public class AccountPriorityGate {

  public enum Priority { ONLINE, BATCH }

  // BIG: separa buckets de prioridad en el score del ZSET
  private static final long BIG = 1_000_000_000_000L;

  private final RedisTemplate<String, String> redis;
  private final DefaultRedisScript<Long> enqueueOrGo;
  private final DefaultRedisScript<Long> releaseAndWake;

  public AccountPriorityGate(RedisTemplate<String, String> redis) {
    this.redis = redis;

    this.enqueueOrGo = new DefaultRedisScript<>();
    this.enqueueOrGo.setResultType(Long.class);
    this.enqueueOrGo.setScriptText(LUA_ENQUEUE_OR_GO);

    this.releaseAndWake = new DefaultRedisScript<>();
    this.releaseAndWake.setResultType(Long.class);
    this.releaseAndWake.setScriptText(LUA_RELEASE_AND_WAKE_CLEANUP);
  }

  public Permit acquire(String accountId,
                        Priority priority,
                        Duration leaseTtl,
                        Duration totalWaitTimeout,
                        Duration waitKeyTtl) {

    String requestId = UUID.randomUUID().toString();

    String qKey = queueKey(accountId);
    String leaseKey = leaseKey(accountId);
    String seqKey = seqKey(accountId);
    String waitKey = waitKey(requestId);

    long prio = (priority == Priority.ONLINE) ? 0L : 1L;

    long deadlineNanos = System.nanoTime() + totalWaitTimeout.toNanos();

    // 1) Enqueue + si soy head, GO inmediato
    Long go = redis.execute(
        enqueueOrGo,
        List.of(qKey, leaseKey, seqKey),
        requestId,
        String.valueOf(prio),
        String.valueOf(BIG),
        String.valueOf(leaseTtl.toMillis())
    );

    if (go != null && go == 1L) {
      return new Permit(accountId, requestId, leaseTtl, waitKeyTtl);
    }

    // 2) Espera bloqueante (sin “puleo masivo”)
    while (System.nanoTime() < deadlineNanos) {
      Duration remaining = Duration.ofNanos(deadlineNanos - System.nanoTime());
      Duration chunk = remaining.compareTo(Duration.ofSeconds(2)) > 0 ? Duration.ofSeconds(2) : remaining;

      // BLPOP wait:{requestId} chunk
      String msg = redis.opsForList().leftPop(waitKey, chunk);

      if ("GO".equals(msg)) {
        // Validación rápida (defensiva)
        String owner = redis.opsForValue().get(leaseKey);
        if (requestId.equals(owner)) {
          return new Permit(accountId, requestId, leaseTtl, waitKeyTtl);
        }
      }

      // Recovery: si soy head y no hay lease, puedo tomarlo (casos raros)
      String head = zsetHead(qKey);
      if (requestId.equals(head)) {
        Boolean ok = redis.opsForValue().setIfAbsent(leaseKey, requestId, leaseTtl);
        if (Boolean.TRUE.equals(ok)) {
          return new Permit(accountId, requestId, leaseTtl, waitKeyTtl);
        }
      }
    }

    // Cleanup best-effort del buzón
    redis.delete(waitKey);
    throw new RuntimeException("Timeout esperando turno por cuenta accountId=" + accountId);
  }

  public final class Permit implements AutoCloseable {
    private final String accountId;
    private final String requestId;
    private final Duration leaseTtl;
    private final Duration waitKeyTtl;
    private boolean released = false;

    Permit(String accountId, String requestId, Duration leaseTtl, Duration waitKeyTtl) {
      this.accountId = accountId;
      this.requestId = requestId;
      this.leaseTtl = leaseTtl;
      this.waitKeyTtl = waitKeyTtl;
    }

    public String requestId() { return requestId; }

    @Override
    public void close() {
      if (released) return;
      released = true;

      String qKey = queueKey(accountId);
      String leaseKey = leaseKey(accountId);
      String seqKey = seqKey(accountId);

      redis.execute(
          releaseAndWake,
          List.of(qKey, leaseKey, seqKey),
          requestId,
          String.valueOf(leaseTtl.toMillis()),
          String.valueOf(waitKeyTtl.toMillis())
      );

      // best-effort cleanup
      redis.delete(waitKey(requestId));
    }
  }

  private String zsetHead(String qKey) {
    var heads = redis.opsForZSet().range(qKey, 0, 0);
    if (heads == null || heads.isEmpty()) return null;
    return heads.iterator().next();
  }

  private static String queueKey(String accountId) { return "acct:{" + accountId + "}:q"; }
  private static String leaseKey(String accountId) { return "acct:{" + accountId + "}:lease"; }
  private static String seqKey(String accountId)   { return "acct:{" + accountId + "}:seq"; }
  private static String waitKey(String requestId)  { return "wait:{" + requestId + "}"; }

  // KEYS: [qKey, leaseKey, seqKey]
  // ARGV: requestId, priority(0/1), BIG, leaseTtlMs
  private static final String LUA_ENQUEUE_OR_GO = """
  local qKey     = KEYS[1]
  local leaseKey = KEYS[2]
  local seqKey   = KEYS[3]

  local requestId = ARGV[1]
  local priority  = tonumber(ARGV[2])
  local BIG       = tonumber(ARGV[3])
  local leaseTtl  = ARGV[4]

  local seq = redis.call('INCR', seqKey)
  local score = (priority * BIG) + seq
  redis.call('ZADD', qKey, score, requestId)

  local headArr = redis.call('ZRANGE', qKey, 0, 0)
  local head = headArr[1]
  if head == requestId then
    local ok = redis.call('SET', leaseKey, requestId, 'NX', 'PX', leaseTtl)
    if ok then return 1 end
  end
  return 0
  """;

  // KEYS: [qKey, leaseKey, seqKey]
  // ARGV: requestId, leaseTtlMs, waitKeyTtlMs
  private static final String LUA_RELEASE_AND_WAKE_CLEANUP = """
  local qKey     = KEYS[1]
  local leaseKey = KEYS[2]
  local seqKey   = KEYS[3]

  local requestId = ARGV[1]
  local leaseTtl  = ARGV[2]
  local waitTtl   = ARGV[3]

  local leaseOwner = redis.call('GET', leaseKey)
  if leaseOwner ~= requestId then
    return -1
  end

  redis.call('ZREM', qKey, requestId)
  redis.call('DEL', leaseKey)

  local nextArr = redis.call('ZRANGE', qKey, 0, 0)
  local next = nextArr[1]

  if next then
    redis.call('SET', leaseKey, next, 'PX', leaseTtl)
    local waitKey = 'wait:{' .. next .. '}'
    redis.call('LPUSH', waitKey, 'GO')
    redis.call('PEXPIRE', waitKey, waitTtl)
    return 1
  end

  -- cola vacía: cleanup y reset de secuencia
  redis.call('DEL', qKey)
  redis.call('DEL', seqKey)
  return 0
  """;
}
