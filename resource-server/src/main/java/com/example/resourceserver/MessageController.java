package com.example.resourceserver;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api")
public class MessageController {

    private final Map<Long, String> messages = new ConcurrentHashMap<>();
    private long seq = 0;

    @GetMapping("/messages")
    @PreAuthorize("hasAuthority('SCOPE_message.read')")
    public List<String> getMessages() {
        return new ArrayList<>(messages.values());
    }

    @PostMapping("/messages")
    @PreAuthorize("hasAuthority('SCOPE_message.write')")
    public String addMessage(@RequestBody String message) {
        messages.put(++seq, message);
        return "Message added: " + message;
    }
}
