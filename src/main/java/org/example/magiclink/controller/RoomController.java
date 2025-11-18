package org.example.magiclink.controller;

import lombok.Data;
import org.example.magiclink.entity.Room;
import org.example.magiclink.service.RoomManager;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/rooms")
public class RoomController {

    private final RoomManager roomManager;

    public RoomController(RoomManager roomManager) {
        this.roomManager = roomManager;
    }

    @PostMapping("/create")
    public ResponseEntity<?> createRoom(@RequestBody CreateRoomRequest request) {
        try {
            Room room = roomManager.createRoom(
                    request.getRoomId(),
                    request.getName(),
                    request.getDescription(),
                    request.getType() != null ? request.getType() : Room.RoomType.PUBLIC,
                    request.getPassword(),
                    request.getCreatedBy(),
                    request.isPersistent()
            );

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Room created successfully",
                    "room", room
            ));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/list")
    public ResponseEntity<?> listRooms() {
        List<Room> rooms = roomManager.getAllRooms();

        List<Map<String, Object>> roomList = rooms.stream()
                .map(room -> Map.of(
                        "roomId", room.getRoomId(),
                        "name", room.getName(),
                        "description", room.getDescription() != null ? room.getDescription() : "",
                        "type", room.getType().toString(),
                        "memberCount", roomManager.getRoomMembers(room.getRoomId()).size(),
                        "persistent", room.isPersistent(),
                        "createdBy", room.getCreatedBy(),
                        "createdAt", room.getCreatedAt().toString()
                ))
                .toList();

        return ResponseEntity.ok(Map.of(
                "success", true,
                "rooms", roomList
        ));
    }

    @GetMapping("/{roomId}")
    public ResponseEntity<?> getRoom(@PathVariable String roomId) {
        Optional<Room> roomOpt = roomManager.getRoomById(roomId);

        if (roomOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Room room = roomOpt.get();
        return ResponseEntity.ok(Map.of(
                "success", true,
                "room", Map.of(
                        "roomId", room.getRoomId(),
                        "name", room.getName(),
                        "description", room.getDescription() != null ? room.getDescription() : "",
                        "type", room.getType().toString(),
                        "memberCount", roomManager.getRoomMembers(room.getRoomId()).size(),
                        "members", roomManager.getRoomMembers(room.getRoomId()),
                        "persistent", room.isPersistent(),
                        "createdBy", room.getCreatedBy(),
                        "createdAt", room.getCreatedAt().toString()
                )
        ));
    }

    @GetMapping("/{roomId}/members")
    public ResponseEntity<?> getRoomMembers(@PathVariable String roomId) {
        Set<String> members = roomManager.getRoomMembers(roomId);

        return ResponseEntity.ok(Map.of(
                "success", true,
                "roomId", roomId,
                "members", members
        ));
    }

    @DeleteMapping("/{roomId}")
    public ResponseEntity<?> deleteRoom(@PathVariable String roomId) {
        boolean deleted = roomManager.deleteRoom(roomId);

        if (deleted) {
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "Room deleted successfully"
            ));
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Data
    public static class CreateRoomRequest {
        private String roomId;
        private String name;
        private String description;
        private Room.RoomType type;
        private String password;
        private String createdBy;
        private boolean persistent;
    }
}
