# Multi-Room Chat Application

This document describes the multi-room WebSocket chat feature that has been added to the Magic Link Service application.

## Overview

The multi-room chat application allows users to create and join multiple chat rooms simultaneously, enabling real-time communication via WebSockets. This is designed to test the server's capability to handle multiple WebSocket connections and chat rooms concurrently.

## Features

- **Create Multiple Chat Rooms**: Users can create as many chat rooms as needed
- **Real-time Messaging**: WebSocket-based instant messaging using STOMP protocol
- **User Join/Leave Notifications**: System messages when users join or leave rooms
- **Typing Indicators**: Real-time typing status display
- **Active User Tracking**: Display of active users in each room
- **Room Management**: REST API for creating, listing, and deleting rooms
- **Persistent Storage**: Chat rooms are stored in the H2 database

## Architecture

### Backend Components

1. **Entities**
   - `ChatRoom` (src/main/java/org/example/magiclink/entity/ChatRoom.java): JPA entity for storing chat room information

2. **Models**
   - `ChatMessage` (src/main/java/org/example/magiclink/model/ChatMessage.java): DTO for WebSocket messages
   - `ChatRoomDTO` (src/main/java/org/example/magiclink/model/ChatRoomDTO.java): DTO for chat room data

3. **Configuration**
   - `WebSocketConfig` (src/main/java/org/example/magiclink/config/WebSocketConfig.java): WebSocket and STOMP configuration
   - `WebSocketEventListener` (src/main/java/org/example/magiclink/config/WebSocketEventListener.java): Handles WebSocket connection/disconnection events

4. **Services**
   - `ChatRoomService` (src/main/java/org/example/magiclink/service/ChatRoomService.java): Business logic for chat room management

5. **Controllers**
   - `ChatController` (src/main/java/org/example/magiclink/controller/ChatController.java): WebSocket message handlers
   - `ChatRoomController` (src/main/java/org/example/magiclink/controller/ChatRoomController.java): REST API endpoints
   - `ChatViewController` (src/main/java/org/example/magiclink/controller/ChatViewController.java): Serves the chat UI

### Frontend Components

- `chat.html`: Main chat interface
- `chat.css`: Styling for the chat application
- `chat.js`: JavaScript for WebSocket communication and UI management

## API Endpoints

### REST API

- `POST /api/chatrooms` - Create a new chat room
  ```json
  {
    "name": "Room Name",
    "description": "Optional description"
  }
  ```

- `GET /api/chatrooms` - Get all chat rooms
- `GET /api/chatrooms/{roomId}` - Get specific room details
- `DELETE /api/chatrooms/{roomId}` - Delete a chat room
- `GET /api/chatrooms/{roomId}/users/count` - Get active user count

### WebSocket Endpoints

- `/ws` - WebSocket connection endpoint (with SockJS fallback)
- `/app/chat/{roomId}/sendMessage` - Send a chat message
- `/app/chat/{roomId}/addUser` - Join a room
- `/app/chat/{roomId}/typing` - Send typing indicator
- `/topic/room/{roomId}` - Subscribe to room messages

## Usage

### Starting the Application

1. Build the application:
   ```bash
   ./gradlew build
   ```

2. Run the application:
   ```bash
   ./gradlew bootRun
   ```

3. Access the chat interface:
   ```
   http://localhost:8080/chat
   ```

### Creating and Joining Rooms

1. **Create a Room**:
   - Enter a room name and optional description
   - Click "Create Room"
   - Note the generated Room ID

2. **Join a Room**:
   - Enter your username
   - Enter or select a Room ID
   - Click "Join Room"

3. **Chat**:
   - Type messages in the input field
   - Press Enter or click Send
   - See real-time messages from other users
   - Observe join/leave notifications

4. **Leave a Room**:
   - Click the "Leave Room" button in the chat header
   - Returns to the room selection screen

### Testing Multiple Rooms

To test the server's capability with multiple rooms:

1. Open multiple browser tabs/windows
2. Create different rooms or join the same room
3. Send messages simultaneously from different tabs
4. Monitor server performance and WebSocket connection handling

## Message Types

The application supports four types of messages:

- `CHAT`: Regular chat messages
- `JOIN`: User joined notification
- `LEAVE`: User left notification
- `TYPING`: Typing indicator

## Technical Details

### WebSocket Configuration

- **Protocol**: STOMP over SockJS
- **Message Broker**: Simple in-memory broker
- **Prefixes**:
  - `/app`: Application destination prefix for client messages
  - `/topic`: Topic prefix for broadcasting messages

### Database Schema

```sql
CREATE TABLE chat_rooms (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    room_id VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL,
    active_users INTEGER NOT NULL DEFAULT 0
);
```

### Security

All chat-related endpoints are configured to permit all access for testing purposes. For production use, consider adding proper authentication and authorization.

## Performance Testing

To test the server's WebSocket capabilities:

1. **Load Testing**: Use tools like Artillery or JMeter with WebSocket plugins
2. **Multiple Rooms**: Create many rooms and monitor memory usage
3. **Concurrent Users**: Simulate multiple users in different rooms
4. **Message Throughput**: Send high volumes of messages and measure latency

Example Artillery test:
```yaml
config:
  target: 'http://localhost:8080'
  phases:
    - duration: 60
      arrivalRate: 10
  engines:
    socketio:
      transports: ['websocket']

scenarios:
  - engine: socketio
    flow:
      - emit:
          channel: '/app/chat/test-room/sendMessage'
          data:
            sender: 'LoadTestUser'
            content: 'Test message'
            type: 'CHAT'
```

## Troubleshooting

### WebSocket Connection Issues

- Check browser console for errors
- Verify CORS settings if accessing from different origin
- Ensure SockJS is properly loaded
- Check server logs for connection attempts

### Messages Not Appearing

- Verify room ID matches between sender and receiver
- Check WebSocket subscription is active
- Ensure STOMP client is connected

### Database Issues

- Check H2 console: `http://localhost:8080/h2-console`
- Verify JDBC URL in application.yml
- Check entity mappings and repository methods

## Future Enhancements

Potential improvements for the chat application:

- Message persistence (save chat history to database)
- User authentication and authorization
- Private messaging between users
- File sharing capabilities
- Message reactions and emoji support
- User presence status
- Room moderation features
- Message search functionality
- Notification system
- Mobile responsive design improvements
