package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import org.example.magiclink.model.ChatRoomDTO;
import org.example.magiclink.service.ChatRoomService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/chatrooms")
@RequiredArgsConstructor
public class ChatRoomController {

    private final ChatRoomService chatRoomService;

    @PostMapping
    public ResponseEntity<ChatRoomDTO> createRoom(@RequestBody Map<String, String> request) {
        String name = request.get("name");
        String description = request.getOrDefault("description", "");

        if (name == null || name.trim().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        ChatRoomDTO chatRoom = chatRoomService.createRoom(name, description);
        return ResponseEntity.ok(chatRoom);
    }

    @GetMapping
    public ResponseEntity<List<ChatRoomDTO>> getAllRooms() {
        List<ChatRoomDTO> rooms = chatRoomService.getAllRooms();
        return ResponseEntity.ok(rooms);
    }

    @GetMapping("/{roomId}")
    public ResponseEntity<ChatRoomDTO> getRoom(@PathVariable String roomId) {
        try {
            ChatRoomDTO room = chatRoomService.getRoomByRoomId(roomId);
            return ResponseEntity.ok(room);
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{roomId}")
    public ResponseEntity<Void> deleteRoom(@PathVariable String roomId) {
        try {
            chatRoomService.deleteRoom(roomId);
            return ResponseEntity.ok().build();
        } catch (RuntimeException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @GetMapping("/{roomId}/users/count")
    public ResponseEntity<Map<String, Integer>> getActiveUserCount(@PathVariable String roomId) {
        int count = chatRoomService.getActiveUserCount(roomId);
        return ResponseEntity.ok(Map.of("activeUsers", count));
    }
}
