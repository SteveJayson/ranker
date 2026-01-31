// --- 1. Import necessary modules ---
require('dotenv').config();
const { Client, GatewayIntentBits, Collection } = require('discord.js');
const axios = require('axios');
const express = require('express');
const bodyParser = require('body-parser');

// --- 2. Configuration from .env ---
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const ROBLOX_COOKIE = process.env.ROBLOX_COOKIE;
const ROBLOX_GROUP_ID = parseInt(process.env.ROBLOX_GROUP_ID);
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const COMMAND_PREFIXES = ['!setrank', '!promote', '!demote'];
const REQUIRED_DISCORD_ROLE = 'Ranker';

const COOLDOWN_SECONDS = 10; 
const PORT = process.env.PORT || 3000;

// --- 3. Initialize Discord Client & Cooldowns ---
const cooldowns = new Collection(); 
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent 
    ] 
});

// --- 4. Axios Session Setup ---
const robloxClient = axios.create({
    baseURL: 'https://groups.roblox.com/v1',
    headers: {
        'Accept': 'application/json',
        'Cookie': `.ROBLOSECURITY=${ROBLOX_COOKIE}`
    },
    validateStatus: function (status) {
        return status >= 200 && status < 300 || status === 403; 
    }
});

async function getXsrfToken() {
    try {
        const tokenResponse = await robloxClient.post('https://accountinformation.roblox.com/v1/birthdate', {}, {
            headers: { 'Content-Type': 'application/json' }
        });
        if (tokenResponse.headers && tokenResponse.headers['x-csrf-token']) {
             return tokenResponse.headers['x-csrf-token'];
        }
        return null; 
    } catch (error) {
        if (error.response && error.response.status === 403) {
            const csrfToken = error.response.headers['x-csrf-token'];
            if (csrfToken) return csrfToken;
        }
        return null;
    }
}

// --- MODIFIED logAction ---
function logAction(source, status, username, currentRole, newRole, error = null) {
    if (!LOG_CHANNEL_ID || !client.isReady()) return; 

    const guild = client.guilds.cache.first();
    if (!guild) return; 

    const logChannel = guild.channels.cache.get(LOG_CHANNEL_ID);
    if (!logChannel) return;

    // MODIFIED: This line now checks for source.executorName (from Roblox) 
    const executor = (source.author && source.author.tag) || source.executorName || 'Roblox Webhook';
    
    const sourceDetail = (source.channel && source.channel.name) || 'Game Server';
    const timestamp = new Date().toLocaleString();
    
    const oldRankName = currentRole ? currentRole.name : 'N/A';
    const oldRankNumber = currentRole ? currentRole.rank : 'N/A';
    const newRankName = newRole ? newRole.name : 'N/A';
    const newRankNumber = newRole ? newRole.rank : 'N/A';
    
    let logMessage = '';
    if (status === 'SUCCESS') {
        const action = oldRankNumber < newRankNumber ? '➡️ Promoted' : (oldRankNumber > newRankNumber ? '⬇️ Demoted' : '➡️ Set Rank');
        logMessage = 
            `**[✅ SUCCESS - RANK ACTION]**\n` +
            `*Source:* **${sourceDetail}**\n` +
            `*Executor:* **${executor}**\n` +
            `*Target User:* **${username}**\n` +
            `*Action:* ${action} from **${oldRankNumber}** to **${newRankNumber}**\n` +
            `*Old Rank:* ${oldRankName} (Rank ${oldRankNumber})\n` +
            `*New Rank:* ${newRankName} (Rank ${newRankNumber})\n` +
            `*Time:* ${timestamp}`;
    } else if (status === 'FAILURE') {
        logMessage = 
            `**[🛑 FAILURE - RANK ACTION]**\n` +
            `*Source:* **${sourceDetail}**\n` +
            `*Executor:* **${executor}**\n` +
            `*Target User:* **${username}**\n` +
            `*Attempted Rank:* ${newRankNumber}\n` +
            `*Error:* ${error}\n` +
            `*Current Rank:* ${oldRankName} (Rank ${oldRankNumber})\n` +
            `*Time:* ${timestamp}`;
    }

    if (logMessage) {
        logChannel.send(logMessage).catch(console.error);
    }
}

// --- 6. Roblox Ranker Logic ---
async function processRobloxRankAction(source, username, rankValue, isAction) {
    let currentRole = null;
    let newRole = null;
    let targetRankNumber = isAction ? null : rankValue; 
    let actionType = isAction ? (rankValue === 1 ? 'promote' : 'demote') : 'set';
    let userId = null;
    
    let replyFunction = (msg) => { 
        if (source.status) {
            return source.status(msg.includes('✅') ? 200 : 400).send({ success: msg.includes('✅'), message: msg });
        } else if (source.reply) {
            return source.reply(msg);
        }
    };

    try {
        const userLookupUrl = 'https://users.roblox.com/v1/usernames/users';
        const userResponse = await robloxClient.post(userLookupUrl, { usernames: [username], excludeBannedUsers: true });
        const userData = userResponse.data.data;
        if (!userData || userData.length === 0) {
            const errorMsg = `Roblox user **${username}** not found.`;
            logAction(source, 'FAILURE', username, null, null, errorMsg);
            return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }
        userId = userData[0].id;

        const membershipUrl = `https://groups.roblox.com/v1/users/${userId}/groups/roles`;
        const membershipResponse = await robloxClient.get(membershipUrl);
        const currentGroup = membershipResponse.data.data.find(g => g.group.id === ROBLOX_GROUP_ID);

        if (!currentGroup) {
            const errorMsg = `User **${username}** is not in the group.`;
            logAction(source, 'FAILURE', username, null, null, errorMsg);
            return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }
        currentRole = currentGroup.role;

        if (isAction) {
            targetRankNumber = currentRole.rank + rankValue;
        }
        
        const rolesResponse = await robloxClient.get(`/groups/${ROBLOX_GROUP_ID}/roles`);
        newRole = rolesResponse.data.roles.find(role => role.rank === targetRankNumber);

        if (!newRole || newRole.rank === 255) {
             const errorMsg = "Invalid rank or cannot set to Owner.";
             logAction(source, 'FAILURE', username, currentRole, null, errorMsg);
             return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }

        const csrfToken = await getXsrfToken();
        await robloxClient.patch(`/groups/${ROBLOX_GROUP_ID}/users/${userId}`, { roleId: newRole.id }, {
            headers: { 'X-CSRF-TOKEN': csrfToken }
        });

        logAction(source, 'SUCCESS', username, currentRole, newRole);
        return replyFunction(`✅ **Success!** User **${username}** ranked to **${newRole.name}**.`);

    } catch (error) {
        logAction(source, 'FAILURE', username, currentRole, null, error.message);
        return replyFunction(`🛑 **Roblox API Error:** ${error.message}`);
    }
}

// --- 8. Discord Listener ---
client.on('messageCreate', async (message) => {
    if (message.author.bot) return;
    const args = message.content.trim().split(/\s+/);
    const command = args[0].toLowerCase();
    if (!COMMAND_PREFIXES.includes(command)) return;

    const requiredRole = message.guild.roles.cache.find(role => role.name === REQUIRED_DISCORD_ROLE);
    if (!requiredRole || !message.member.roles.cache.has(requiredRole.id)) return;

    if (command === '!setrank') {
        await processRobloxRankAction(message, args[1], parseInt(args[2]), false);
    } else {
        await processRobloxRankAction(message, args[1], command === '!promote' ? 1 : -1, true);
    }
});

// --- 9. MODIFIED Webhook Setup ---
const app = express();
app.use(bodyParser.json());

app.post('/rank-webhook', async (req, res) => {
    // MODIFIED: Added 'executor' to the destruction list
    const { secret, username, action, rank_number, executor } = req.body;

    if (!secret || secret !== WEBHOOK_SECRET) {
        return res.status(401).send({ success: false, message: 'Invalid secret.' });
    }

    // MODIFIED: Attach the executor name to the response object so logAction can find it
    res.executorName = executor || "Unknown Staff";

    let rankValue, isAction;
    if (action === 'promote') { rankValue = 1; isAction = true; }
    else if (action === 'demote') { rankValue = -1; isAction = true; }
    else { rankValue = parseInt(rank_number); isAction = false; }

    await processRobloxRankAction(res, username, rankValue, isAction);
});

client.on('ready', () => {
    console.log(`🤖 Bot Ready!`);
    app.listen(PORT, () => console.log(`📡 Server on port ${PORT}`));
});

client.login(DISCORD_TOKEN);
