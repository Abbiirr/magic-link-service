package org.example.magiclink.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.magiclink.model.ChatMessage;
import org.example.magiclink.service.ChatRoomService;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.stereotype.Controller;

import java.time.LocalDateTime;

@Controller
@RequiredArgsConstructor
@Slf4j
public class ChatController {

    private final ChatRoomService chatRoomService;

    @MessageMapping("/chat/{roomId}/sendMessage")
    @SendTo("/topic/room/{roomId}")
    public ChatMessage sendMessage(@DestinationVariable String roomId,
                                   @Payload ChatMessage chatMessage) {
        chatMessage.setTimestamp(LocalDateTime.now());
        chatMessage.setRoomId(roomId);
        log.info("Message sent to room {}: {} by {}", roomId, chatMessage.getContent(), chatMessage.getSender());
        return chatMessage;
    }

    @MessageMapping("/chat/{roomId}/addUser")
    @SendTo("/topic/room/{roomId}")
    public ChatMessage addUser(@DestinationVariable String roomId,
                               @Payload ChatMessage chatMessage,
                               SimpMessageHeaderAccessor headerAccessor) {

        // Add username and roomId to websocket session
        headerAccessor.getSessionAttributes().put("username", chatMessage.getSender());
        headerAccessor.getSessionAttributes().put("roomId", roomId);

        chatMessage.setTimestamp(LocalDateTime.now());
        chatMessage.setRoomId(roomId);
        chatMessage.setType(ChatMessage.MessageType.JOIN);

        // Update active user count
        chatRoomService.userJoinedRoom(roomId);

        log.info("User {} joined room {}", chatMessage.getSender(), roomId);
        return chatMessage;
    }

    @MessageMapping("/chat/{roomId}/typing")
    @SendTo("/topic/room/{roomId}")
    public ChatMessage typing(@DestinationVariable String roomId,
                             @Payload ChatMessage chatMessage) {
        chatMessage.setTimestamp(LocalDateTime.now());
        chatMessage.setRoomId(roomId);
        chatMessage.setType(ChatMessage.MessageType.TYPING);
        return chatMessage;
    }
}
