const WebSocket = require('ws');
const http = require('http');
const https = require('https');
const fs = require('fs');

// Create HTTP server for WebSocket
const server = http.createServer();

// Create WebSocket server
const wss = new WebSocket.Server({ 
  server,
  perMessageDeflate: false
});

// Start server on port 10000 for local development
const PORT = process.env.PORT || 10000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 WebSocket server running on port ${PORT}`);
  console.log(`🌐 Accessible at: ws://localhost:${PORT} (local) or wss://launch-page-sonn.onrender.com (production)`);
});

let launchState = {
  clickCount: 0,
  isLaunched: false,
  participants: [],
  launchTime: null,
  revealComplete: false
};

// Enhanced logging
function logState(action) {
  console.log(`[${new Date().toISOString()}] ${action} - Count: ${launchState.clickCount}, Launched: ${launchState.isLaunched}, Participants: ${launchState.participants.length}`);
}

// Broadcast to all connected clients
function broadcast(data) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
  console.log(`Broadcasting to ${wss.clients.size} clients`);
}

// Handle client connections
wss.on('connection', (ws) => {
  console.log(`New client connected. Total clients: ${wss.clients.size}`);
  
  // Send current state to new client
  ws.send(JSON.stringify(launchState));
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'launch_click') {
        // Only accept clicks if not already launched and user hasn't clicked
        if (!launchState.isLaunched && !launchState.participants.includes(data.userId)) {
          launchState.participants.push(data.userId);
          launchState.clickCount = launchState.participants.length;
          
          // Check if we've reached 3 clicks
          if (launchState.clickCount >= 20) {
            launchState.isLaunched = true;
            launchState.launchTime = new Date().toISOString();
          }
          
          logState(`Click from ${data.userId.substring(0, 8)}`);
          broadcast(launchState);
        }
      } else if (data.type === 'reveal_now') {
        launchState.revealComplete = true;
        logState('Reveal completed');
        broadcast(launchState);
      } else if (data.type === 'reset') {
        // Reset the launch state
        launchState = {
          clickCount: 0,
          isLaunched: false,
          participants: [],
          launchTime: null,
          revealComplete: false
        };
        logState('Launch reset');
        broadcast(launchState);
      }
    } catch (error) {
      console.error('Error processing message:', error);
    }
  });
  
  ws.on('close', () => {
    console.log(`Client disconnected. Total clients: ${wss.clients.size - 1}`);
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

console.log('🚀 Enhanced WebSocket server running on port 10000');
console.log('📊 Initial launch state:', launchState);

// Periodic status logging
setInterval(() => {
  if (wss.clients.size > 0) {
    console.log(`📈 Status: ${wss.clients.size} clients connected, ${launchState.clickCount}/20 participants`);
  }
}, 30000); // Log every 30 seconds if there are active clients