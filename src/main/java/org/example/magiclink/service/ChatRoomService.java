package org.example.magiclink.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.entity.ChatRoom;
import org.example.magiclink.model.ChatRoomDTO;
import org.example.magiclink.repository.ChatRoomRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ChatRoomService {

    private final ChatRoomRepository chatRoomRepository;

    // Track active users per room in memory
    private final Map<String, Integer> activeUsersMap = new ConcurrentHashMap<>();

    @Transactional
    public ChatRoomDTO createRoom(String name, String description) {
        String roomId = UUID.randomUUID().toString();

        ChatRoom chatRoom = ChatRoom.builder()
                .roomId(roomId)
                .name(name)
                .description(description)
                .activeUsers(0)
                .build();

        chatRoom = chatRoomRepository.save(chatRoom);
        activeUsersMap.put(roomId, 0);

        return mapToDTO(chatRoom);
    }

    @Transactional(readOnly = true)
    public List<ChatRoomDTO> getAllRooms() {
        return chatRoomRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ChatRoomDTO getRoomByRoomId(String roomId) {
        ChatRoom chatRoom = chatRoomRepository.findByRoomId(roomId)
                .orElseThrow(() -> new RuntimeException("Chat room not found: " + roomId));
        return mapToDTO(chatRoom);
    }

    @Transactional
    public void userJoinedRoom(String roomId) {
        activeUsersMap.compute(roomId, (key, count) -> (count == null ? 0 : count) + 1);
        updateActiveUsers(roomId);
    }

    @Transactional
    public void userLeftRoom(String roomId) {
        activeUsersMap.compute(roomId, (key, count) -> {
            if (count == null || count <= 0) return 0;
            return count - 1;
        });
        updateActiveUsers(roomId);
    }

    @Transactional
    public void deleteRoom(String roomId) {
        ChatRoom chatRoom = chatRoomRepository.findByRoomId(roomId)
                .orElseThrow(() -> new RuntimeException("Chat room not found: " + roomId));
        chatRoomRepository.delete(chatRoom);
        activeUsersMap.remove(roomId);
    }

    private void updateActiveUsers(String roomId) {
        chatRoomRepository.findByRoomId(roomId).ifPresent(room -> {
            room.setActiveUsers(activeUsersMap.getOrDefault(roomId, 0));
            chatRoomRepository.save(room);
        });
    }

    public int getActiveUserCount(String roomId) {
        return activeUsersMap.getOrDefault(roomId, 0);
    }

    private ChatRoomDTO mapToDTO(ChatRoom chatRoom) {
        return ChatRoomDTO.builder()
                .roomId(chatRoom.getRoomId())
                .name(chatRoom.getName())
                .description(chatRoom.getDescription())
                .activeUsers(activeUsersMap.getOrDefault(chatRoom.getRoomId(), chatRoom.getActiveUsers()))
                .createdAt(chatRoom.getCreatedAt())
                .build();
    }
}
