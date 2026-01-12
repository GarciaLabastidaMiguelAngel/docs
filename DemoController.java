package com.tuorg.apigate.web;

import com.tuorg.apigate.gate.AccountPriorityGate;
import com.tuorg.apigate.web.dto.DemoRequest;
import java.time.Duration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/demo")
public class DemoController {

  private final AccountPriorityGate gate;

  public DemoController(AccountPriorityGate gate) {
    this.gate = gate;
  }

  @PostMapping("/charge")
  public ResponseEntity<?> charge(@RequestBody DemoRequest req) throws Exception {

    var prio = AccountPriorityGate.Priority.valueOf(req.type());

    try (var permit = gate.acquire(
        req.accountId(),
        prio,
        Duration.ofSeconds(15), // lease TTL > tiempo core (simulado)
        Duration.ofSeconds(10), // total wait timeout (sync)
        Duration.ofSeconds(30)  // waitKey TTL
    )) {
      // Simulación del core (sustituye con tu cliente real)
      Thread.sleep(700);

      return ResponseEntity.ok("""
        {"status":"OK","accountId":"%s","requestId":"%s","priority":"%s"}
        """.formatted(req.accountId(), permit.requestId(), prio));
    }
  }
}
