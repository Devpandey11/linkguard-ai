require('dotenv').config();
const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path'); // ✅ added

const app = express();
const cache = new NodeCache({ stdTTL: 3600 });
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ✅ STATIC FILES SERVE (IMPORTANT FIX)
app.use(express.static("public"));

// ✅ ROOT ROUTE FIX (Cannot GET / ka solution)
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use('/analyze', rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20
}));

app.post('/analyze', async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) return res.status(400).json({ error: "URL required" });

        if (cache.has(url)) return res.json(cache.get(url));

        let result = {
            status: "SAFE",
            risk: "LOW",
            reason: "No threats detected.",
            source: "System",
            details: { malicious: 0, suspicious: 0, harmless: 0 },
            explanation: ""
        };

        let domain = "";
        let isLogin = false;
        let isBrandSpoof = false;

        try {
            domain = new URL(url).hostname;
            isLogin = url.toLowerCase().includes("login") || url.toLowerCase().includes("signin");

            const brands = ["facebook", "google", "bank", "paypal", "instagram", "youtube"];
            isBrandSpoof = brands.some(b => domain.includes(b)) && !domain.endsWith(".com");

        } catch {}

        // ================= SAFE BROWSING =================
        try {
            const gsbRes = await axios.post(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_API_KEY}`,
                {
                    client: { clientId: "linkguard", clientVersion: "1.0" },
                    threatInfo: {
                        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                        platformTypes: ["ANY_PLATFORM"],
                        threatEntryTypes: ["URL"],
                        threatEntries: [{ url }]
                    }
                }
            );

            if (gsbRes.data?.matches) {
                result.status = "DANGEROUS";
                result.risk = "HIGH";
                result.reason = "Flagged by Google Safe Browsing.";
                result.source = "Google Safe Browsing";
            }

        } catch (e) {
            console.log("Safe Browsing error:", e.message);
        }

        // ================= VIRUSTOTAL =================
        if (result.status !== "DANGEROUS") {
            try {
                const encoded = Buffer.from(url).toString('base64').replace(/=/g, '');

                const vtRes = await axios.get(
                    `https://www.virustotal.com/api/v3/urls/${encoded}`,
                    { headers: { 'x-apikey': process.env.VT_API_KEY } }
                );

                const stats = vtRes.data?.data?.attributes?.last_analysis_stats;

                if (stats) {
                    result.details = {
                        malicious: stats.malicious || 0,
                        suspicious: stats.suspicious || 0,
                        harmless: stats.harmless || 0
                    };

                    if (stats.malicious > 0) {
                        result.status = "SUSPICIOUS";
                        result.risk = "MEDIUM";
                        result.reason = `Flagged by ${stats.malicious} vendors.`;
                        result.source = "VirusTotal";
                    }
                }

            } catch (e) {
                console.log("VT error:", e.message);
            }
        }

        // ================= AI =================
        try {
            const aiRes = await axios.post(
                "https://openrouter.ai/api/v1/chat/completions",
                {
                    model: "openai/gpt-3.5-turbo",
                    messages: [
                        {
                            role: "user",
                            content: `
Analyze this website:
URL: ${url}
Domain: ${domain}
Status: ${result.status}
Risk: ${result.risk}
Login Page: ${isLogin}
Brand Spoof Risk: ${isBrandSpoof}

Explain simply (4-5 lines).
`
                        }
                    ]
                },
                {
                    headers: {
                        "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            result.explanation =
                aiRes.data?.choices?.[0]?.message?.content ||
                "AI unavailable";

        } catch (e) {
            console.log("AI error:", e.message);

            result.explanation = `
This appears to be a ${isLogin ? "login-related" : "general"} website (${domain}).
Risk level is ${result.risk}.
${isBrandSpoof ? "The domain may mimic a known brand." : ""}
Avoid entering sensitive information unless trusted.
`;
        }

        cache.set(url, result);
        return res.json(result);

    } catch (err) {
        console.error("Server error:", err.message);
        return res.status(500).json({ error: "Analysis failed" });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});
