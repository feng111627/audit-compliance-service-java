package com.github.feng111627.auditcomplianceservicejava.web;

import com.github.feng111627.auditcomplianceservicejava.alert.SimulatedDownstreamClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/** 测试辅助：切换模拟下游模式 / 注入临时故障次数 / 查看投递情况。 */
@RestController
@RequestMapping("/api/test/downstream")
public class SimulatedDownstreamController {

    private final SimulatedDownstreamClient downstream;

    public SimulatedDownstreamController(SimulatedDownstreamClient downstream) {
        this.downstream = downstream;
    }

    @PostMapping("/mode")
    public ResponseEntity<?> setMode(@RequestBody Map<String, String> body) {
        String mode = body.get("mode");
        if (mode == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "缺少 mode"));
        }
        try {
            SimulatedDownstreamClient.Mode m = SimulatedDownstreamClient.Mode.valueOf(mode);
            downstream.setMode(m);
            if (body.containsKey("failNextTimes")) {
                downstream.failNextTimes(Integer.parseInt(body.get("failNextTimes")));
            }
            return ResponseEntity.ok(Map.of("mode", m.name()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "非法 mode，可选 OK/UNREACHABLE/TIMEOUT/DUPLICATE_ACK", "detail", e.getMessage()));
        }
    }

    @GetMapping
    public Map<String, Object> status() {
        return Map.of(
                "mode", downstream.getMode().name(),
                "deliveredSeqs", downstream.getDeliveredSeqs(),
                "receivedCount", downstream.getReceived().size());
    }
}
