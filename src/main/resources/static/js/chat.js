let stompClient = null;
let currentRoomId = null;
let currentUsername = null;
let typingTimeout = null;

const API_BASE_URL = '/api/chatrooms';

// Load rooms on page load
window.addEventListener('DOMContentLoaded', () => {
    loadRooms();
});

async function createRoom() {
    const name = document.getElementById('room-name').value.trim();
    const description = document.getElementById('room-description').value.trim();

    if (!name) {
        alert('Please enter a room name');
        return;
    }

    try {
        const response = await fetch(API_BASE_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, description }),
        });

        if (response.ok) {
            const room = await response.json();
            alert(`Room created successfully! Room ID: ${room.roomId}`);
            document.getElementById('room-name').value = '';
            document.getElementById('room-description').value = '';
            loadRooms();
        } else {
            alert('Failed to create room');
        }
    } catch (error) {
        console.error('Error creating room:', error);
        alert('Error creating room');
    }
}

async function loadRooms() {
    try {
        const response = await fetch(API_BASE_URL);
        const rooms = await response.json();

        const roomsList = document.getElementById('rooms-list');
        roomsList.innerHTML = '';

        if (rooms.length === 0) {
            roomsList.innerHTML = '<p>No rooms available. Create one to get started!</p>';
            return;
        }

        rooms.forEach(room => {
            const roomDiv = document.createElement('div');
            roomDiv.className = 'room-item';
            roomDiv.onclick = () => selectRoom(room.roomId);

            roomDiv.innerHTML = `
                <h3>${room.name}</h3>
                <p>${room.description || 'No description'}</p>
                <div class="room-meta">
                    Room ID: ${room.roomId} | Active Users: ${room.activeUsers || 0}
                </div>
            `;
            roomsList.appendChild(roomDiv);
        });
    } catch (error) {
        console.error('Error loading rooms:', error);
        document.getElementById('rooms-list').innerHTML = '<p>Error loading rooms</p>';
    }
}

function selectRoom(roomId) {
    document.getElementById('room-id-input').value = roomId;
}

function joinRoom() {
    const username = document.getElementById('username').value.trim();
    const roomId = document.getElementById('room-id-input').value.trim();

    if (!username) {
        alert('Please enter a username');
        return;
    }

    if (!roomId) {
        alert('Please enter or select a room ID');
        return;
    }

    currentUsername = username;
    currentRoomId = roomId;

    // Load room info
    loadRoomInfo(roomId);

    // Switch screens
    document.getElementById('room-selection').classList.remove('active');
    document.getElementById('chat-screen').classList.add('active');

    // Connect to WebSocket
    connect();
}

async function loadRoomInfo(roomId) {
    try {
        const response = await fetch(`${API_BASE_URL}/${roomId}`);
        if (response.ok) {
            const room = await response.json();
            document.getElementById('current-room-name').textContent = room.name;
            document.getElementById('current-room-id').textContent = room.roomId;
            document.getElementById('active-users').textContent = room.activeUsers || 0;
        }
    } catch (error) {
        console.error('Error loading room info:', error);
    }
}

function connect() {
    const socket = new SockJS('/ws');
    stompClient = Stomp.over(socket);

    stompClient.connect({}, onConnected, onError);
}

function onConnected() {
    // Subscribe to the room
    stompClient.subscribe(`/topic/room/${currentRoomId}`, onMessageReceived);

    // Tell other users that we joined
    stompClient.send(
        `/app/chat/${currentRoomId}/addUser`,
        {},
        JSON.stringify({ sender: currentUsername, type: 'JOIN' })
    );

    updateActiveUserCount();
}

function onError(error) {
    console.error('WebSocket connection error:', error);
    alert('Could not connect to WebSocket server. Please refresh and try again.');
}

function sendMessage() {
    const messageInput = document.getElementById('message-input');
    const messageContent = messageInput.value.trim();

    if (messageContent && stompClient) {
        const chatMessage = {
            sender: currentUsername,
            content: messageContent,
            type: 'CHAT',
        };

        stompClient.send(
            `/app/chat/${currentRoomId}/sendMessage`,
            {},
            JSON.stringify(chatMessage)
        );

        messageInput.value = '';
    }
}

function handleTyping(event) {
    if (event.key === 'Enter') {
        sendMessage();
        return;
    }

    if (!stompClient) return;

    // Clear existing timeout
    if (typingTimeout) {
        clearTimeout(typingTimeout);
    }

    // Send typing indicator
    stompClient.send(
        `/app/chat/${currentRoomId}/typing`,
        {},
        JSON.stringify({ sender: currentUsername, type: 'TYPING' })
    );

    // Clear typing indicator after 2 seconds
    typingTimeout = setTimeout(() => {
        document.getElementById('typing-indicator').textContent = '';
    }, 2000);
}

function onMessageReceived(payload) {
    const message = JSON.parse(payload.body);

    const messagesArea = document.getElementById('messages-area');

    if (message.type === 'JOIN') {
        displaySystemMessage(`${message.sender} joined the room`);
        updateActiveUserCount();
    } else if (message.type === 'LEAVE') {
        displaySystemMessage(`${message.sender} left the room`);
        updateActiveUserCount();
    } else if (message.type === 'TYPING') {
        if (message.sender !== currentUsername) {
            document.getElementById('typing-indicator').textContent = `${message.sender} is typing...`;
        }
    } else if (message.type === 'CHAT') {
        displayChatMessage(message);
    }
}

function displayChatMessage(message) {
    const messagesArea = document.getElementById('messages-area');
    const messageDiv = document.createElement('div');

    const isOwnMessage = message.sender === currentUsername;
    messageDiv.className = `message ${isOwnMessage ? 'own' : 'chat'}`;

    const timestamp = new Date(message.timestamp).toLocaleTimeString();

    messageDiv.innerHTML = `
        ${!isOwnMessage ? `<div class="sender">${message.sender}</div>` : ''}
        <div class="content">${escapeHtml(message.content)}</div>
        <div class="timestamp">${timestamp}</div>
    `;

    messagesArea.appendChild(messageDiv);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function displaySystemMessage(content) {
    const messagesArea = document.getElementById('messages-area');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'message system';
    messageDiv.innerHTML = `<div class="content">${content}</div>`;
    messagesArea.appendChild(messageDiv);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

async function updateActiveUserCount() {
    try {
        const response = await fetch(`${API_BASE_URL}/${currentRoomId}/users/count`);
        if (response.ok) {
            const data = await response.json();
            document.getElementById('active-users').textContent = data.activeUsers;
        }
    } catch (error) {
        console.error('Error updating user count:', error);
    }
}

function leaveRoom() {
    if (stompClient) {
        stompClient.disconnect();
    }

    // Reset state
    currentRoomId = null;
    currentUsername = null;
    document.getElementById('messages-area').innerHTML = '';
    document.getElementById('username').value = '';
    document.getElementById('room-id-input').value = '';

    // Switch screens
    document.getElementById('chat-screen').classList.remove('active');
    document.getElementById('room-selection').classList.add('active');

    // Reload rooms
    loadRooms();
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}
