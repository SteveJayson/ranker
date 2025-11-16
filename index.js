// --- 1. Import necessary modules ---
require('dotenv').config();
// IMPORTANT: Need to import Collection for cooldowns
const { Client, GatewayIntentBits, Collection } = require('discord.js');
const axios = require('axios');

// --- 2. Configuration from .env ---
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const ROBLOX_COOKIE = process.env.ROBLOX_COOKIE;
const ROBLOX_GROUP_ID = parseInt(process.env.ROBLOX_GROUP_ID);
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID; // NEW: Log Channel ID
const COMMAND_PREFIXES = ['!setrank', '!promote', '!demote'];
const REQUIRED_DISCORD_ROLE = 'Ranker'; // The Discord role required to use the command

// --- NEW: Cooldown Configuration ---
const COOLDOWN_SECONDS = 10; // Cooldown per user, per command

// --- 3. Initialize Discord Client ---
// Initialize a Collection to store cooldowns (Required for cooldowns)
const cooldowns = new Collection(); 
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent 
    ] 
});

// --- 4. Axios Session Setup (Roblox API Client) ---
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

// --- 5. Bot Events ---

client.on('ready', () => {
    console.log(`🤖 Logged in as ${client.user.tag}!`);
    
    // Initial check to ensure the cookie is valid
    robloxClient.get('https://users.roblox.com/v1/users/authenticated')
        .then(response => {
            console.log(`✅ Roblox bot authenticated as: ${response.data.name} (ID: ${response.data.id})`);
            console.log(`🌎 Group ID: ${ROBLOX_GROUP_ID}`);
            if (LOG_CHANNEL_ID) {
                console.log(`📜 Log Channel ID: ${LOG_CHANNEL_ID}`);
            }
        })
        .catch(error => {
            console.error('ERROR: Roblox authentication failed. Check ROBLOX_COOKIE.');
        });
});

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    const args = message.content.trim().split(/\s+/);
    const command = args[0].toLowerCase();
    
    if (!COMMAND_PREFIXES.includes(command)) return;

    // --- COOLDOWN CHECK ---
    if (!cooldowns.has(command)) {
        cooldowns.set(command, new Collection());
    }

    const now = Date.now();
    const timestamps = cooldowns.get(command);
    const cooldownAmount = COOLDOWN_SECONDS * 1000;
    const userId = message.author.id;

    if (timestamps.has(userId)) {
        const expirationTime = timestamps.get(userId) + cooldownAmount;

        if (now < expirationTime) {
            const timeLeft = (expirationTime - now) / 1000;
            return message.reply(`⏳ Please wait **${timeLeft.toFixed(1)} more second(s)** before reusing the \`${command}\` command.`);
        }
    }
    
    timestamps.set(userId, now);
    setTimeout(() => timestamps.delete(userId), cooldownAmount);


    // --- PERMISSION CHECK ---
    const requiredRole = message.guild.roles.cache.find(role => role.name === REQUIRED_DISCORD_ROLE);
    if (!requiredRole || !message.member.roles.cache.has(requiredRole.id)) {
        return message.reply(`🛑 **Permission Denied!** You must have the **${REQUIRED_DISCORD_ROLE}** role to use this command.`);
    }

    // --- COMMAND PARSING ---
    if (command === '!setrank') {
        if (args.length !== 3) {
            return message.reply("🛑 **Invalid Input:** Please use the format `!setrank <RobloxUsername> <RankNumber>`.");
        }
        const username = args[1];
        const targetRankNumber = parseInt(args[2]);

        if (isNaN(targetRankNumber) || targetRankNumber < 1 || targetRankNumber > 255) {
            return message.reply("🛑 **Invalid Rank:** The rank number must be a valid number between 1 and 255.");
        }
        await processRobloxRankAction(message, username, targetRankNumber, false);

    } else if (command === '!promote' || command === '!demote') {
        if (args.length !== 2) {
            return message.reply(`🛑 **Invalid Input:** Please use the format \`${command} <RobloxUsername>\`.`);
        }
        const username = args[1];
        const rankModifier = command === '!promote' ? 1 : -1;
        
        await processRobloxRankAction(message, username, rankModifier, true);
    }
});

// --- 6. Helper Functions ---

async function getXsrfToken() {
    try {
        const tokenResponse = await robloxClient.post('https://accountinformation.roblox.com/v1/birthdate', {}, {
            headers: { 'Content-Type': 'application/json' }
        });
        
        // This is primarily for the case where the POST request is successful (rare, but possible)
        if (tokenResponse.headers && tokenResponse.headers['x-csrf-token']) {
             return tokenResponse.headers['x-csrf-token'];
        }
        return null; 
    } catch (error) {
        // The most common case: Roblox returns 403, and the token is in the error response headers
        if (error.response && error.response.status === 403) {
            const csrfToken = error.response.headers['x-csrf-token'];
            if (csrfToken) {
                return csrfToken;
            }
        }
        // If the error isn't 403 with a token, the cookie is likely bad
        return null;
    }
}

// --- Log Action Function (FIXED to prevent crash on null ranks) ---
function logAction(message, status, username, currentRole, newRole, error = null) {
    if (!LOG_CHANNEL_ID) return; 

    const logChannel = message.guild.channels.cache.get(LOG_CHANNEL_ID);
    if (!logChannel) {
        console.error(`ERROR: Log channel with ID ${LOG_CHANNEL_ID} not found.`);
        return;
    }

    let logMessage = '';
    const executor = message.author.tag;
    const timestamp = new Date().toLocaleString();
    
    // Safely retrieve rank data, defaulting to 'N/A' if the role is null (e.g., if user wasn't in the group)
    const oldRankName = currentRole ? currentRole.name : 'N/A';
    const oldRankNumber = currentRole ? currentRole.rank : 'N/A';
    const newRankName = newRole ? newRole.name : 'N/A';
    const newRankNumber = newRole ? newRole.rank : 'N/A';
    
    if (status === 'SUCCESS') {
        const action = oldRankNumber < newRankNumber ? '➡️ Promoted' : (oldRankNumber > newRankNumber ? '⬇️ Demoted' : '➡️ Set Rank');
        logMessage = 
            `**[✅ SUCCESS - RANK ACTION]**\n` +
            `*Executor:* ${executor}\n` +
            `*Target User:* **${username}**\n` +
            `*Action:* ${action} from **${oldRankNumber}** to **${newRankNumber}**\n` +
            `*Old Rank:* ${oldRankName} (Rank ${oldRankNumber})\n` +
            `*New Rank:* ${newRankName} (Rank ${newRankNumber})\n` +
            `*Time:* ${timestamp}`;
    } else if (status === 'FAILURE') {
        logMessage = 
            `**[🛑 FAILURE - RANK ACTION]**\n` +
            `*Executor:* ${executor}\n` +
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


// --- 7. Roblox Ranker Logic (Unified for all commands) ---

async function processRobloxRankAction(message, username, rankValue, isAction) {
    let currentRole = null;
    let newRole = null;
    let targetRankNumber = isAction ? null : rankValue; 
    let actionType = isAction ? (rankValue === 1 ? 'promote' : 'demote') : 'set';
    let userId = null;

    try {
        // --- A. Get User ID ---
        const userLookupUrl = 'https://users.roblox.com/v1/usernames/users';
        const userResponse = await robloxClient.post(userLookupUrl, { usernames: [username], excludeBannedUsers: true });
        
        const userData = userResponse.data.data;
        if (!userData || userData.length === 0) {
            const errorMsg = `Roblox user ${username} not found.`;
            message.reply(`🛑 **Error:** ${errorMsg}`);
            logAction(message, 'FAILURE', username, null, null, errorMsg);
            return;
        }
        userId = userData[0].id;

        // --- B. Get Current Rank ---
        const membershipUrl = `https://groups.roblox.com/v1/users/${userId}/groups/roles`;
        const membershipResponse = await robloxClient.get(membershipUrl);
        const groupMemberships = membershipResponse.data.data;
        const currentGroup = groupMemberships.find(g => g.group.id === ROBLOX_GROUP_ID);

        if (!currentGroup) {
            const errorMsg = `User ${username} is not a member of the group.`;
            message.reply(`🛑 **Error:** ${errorMsg}`);
            logAction(message, 'FAILURE', username, null, null, errorMsg);
            return;
        }
        currentRole = currentGroup.role;

        // --- C. Calculate Target Rank Number if Promoting/Demoting ---
        if (isAction) {
            targetRankNumber = currentRole.rank + rankValue;
            
            if (targetRankNumber < 1) {
                const errorMsg = "Cannot demote further (user is at the lowest rank).";
                message.reply(`🛑 **Limit Reached:** ${errorMsg}`);
                logAction(message, 'FAILURE', username, currentRole, null, errorMsg);
                return;
            }
            if (targetRankNumber > 255) {
                const errorMsg = "Cannot promote further (user is at the highest rank).";
                message.reply(`🛑 **Limit Reached:** ${errorMsg}`);
                logAction(message, 'FAILURE', username, currentRole, null, errorMsg);
                return;
            }
        }
        
        // --- D. Get All Roles and find Target Role based on Rank Number ---
        const rolesUrl = `/groups/${ROBLOX_GROUP_ID}/roles`;
        const rolesResponse = await robloxClient.get(rolesUrl);
        const rolesData = rolesResponse.data.roles;

        newRole = rolesData.find(role => role.rank === targetRankNumber);

        if (!newRole) {
             const validRanks = rolesData.map(role => role.rank).filter(r => r > 0 && r < 255).sort((a,b) => a-b).join(', ');
             const errorMsg = `Cannot find a role with rank number ${targetRankNumber}. Valid ranks: ${validRanks}`;
             message.reply(`🛑 **Error:** ${errorMsg}`);
             logAction(message, 'FAILURE', username, currentRole, null, errorMsg);
             return;
        }

        // Check for owner rank
        if (newRole.rank === 255) {
             const errorMsg = "Cannot set a user's rank to Owner (Rank 255).";
             message.reply("🛑 **Permission Error:** " + errorMsg);
             logAction(message, 'FAILURE', username, currentRole, null, errorMsg);
             return;
        }

        // Check if rank is the same
        if (currentRole.rank === newRole.rank) {
             const errorMsg = `User ${username} is already at the rank you attempted to ${actionType} them to (${newRole.name}). No change was made.`;
             message.reply(`🛑 **API Error:** ${errorMsg}`);
             logAction(message, 'FAILURE', username, currentRole, newRole, errorMsg);
             return;
        }

        // --- E. Get CSRF Token ---
        const csrfToken = await getXsrfToken();
        if (!csrfToken) {
             const errorMsg = "Could not obtain X-CSRF-TOKEN. Please check your ROBLOX_COOKIE and group permissions.";
             message.reply("🛑 **Authentication Error:** " + errorMsg);
             logAction(message, 'FAILURE', username, currentRole, newRole, errorMsg);
             return;
        }

        // --- F. Execute Rank Change (Corrected Endpoint) ---
        const rankChangeUrl = `/groups/${ROBLOX_GROUP_ID}/users/${userId}`; 
        const rankChangePayload = { roleId: newRole.id }; 
        
        await robloxClient.patch(rankChangeUrl, rankChangePayload, {
            headers: { 'X-CSRF-TOKEN': csrfToken }
        });

        // G. Success Response
        const actionText = actionType.charAt(0).toUpperCase() + actionType.slice(1) + 'd';
        message.reply(
            `✅ **Success!** User **${username}** has been **${actionText}**.\n` +
            `**Old Rank:** ${currentRole.name} (Rank ${currentRole.rank})\n` +
            `**New Rank:** ${newRole.name} (Rank ${newRole.rank})`
        );
        
        // Log the successful action
        logAction(message, 'SUCCESS', username, currentRole, newRole);

    } catch (error) {
        // --- FAILURE HANDLING ---
        let errorMessage = "An unknown network or API error occurred.";
        
        if (error.response) {
            console.error(`Roblox API Request Failed with HTTP Status: ${error.response.status}`);

            if (error.response.data && error.response.data.errors) {
                 const apiError = error.response.data.errors[0];
                 const code = apiError.code;
                 const message = apiError.message;
                 
                 errorMessage = `API Error (Code ${code}): ${message}`;
                 
                 if (code === 10) {
                     errorMessage = "Insufficient permissions. The bot's Rank 250 account cannot rank this user (Are you trying to rank someone higher or at the same rank?).";
                 }
            } else if (error.response.status === 403) {
                errorMessage = "Authentication or Permission Error (403). **Please get a new, fresh ROBLOX_COOKIE and check Rank 250 permissions.**";
            } else if (error.response.status === 404) {
                errorMessage = "API Endpoint Not Found (404). Check the ROBLOX_GROUP_ID.";
            }
        } else if (error.request) {
            errorMessage = "Network Error: No response received from Roblox API.";
        } else {
             errorMessage = `Critical Error: ${error.message}`;
        }
        
        message.reply(`🛑 **Roblox API Error:** ${errorMessage}`);

        // Log the failure
        logAction(message, 'FAILURE', username, currentRole, null, errorMessage);
    }
}


// --- 8. Log in to Discord ---
client.login(DISCORD_TOKEN);
