import { clerkClient } from "@clerk/express";

// Middleware to check userId and plan
export const auth = async (req, res, next) => {
  try {
    // Trim the Authorization header to remove spaces or line breaks
    const authHeader = req.headers['authorization']?.trim();

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Missing or invalid Authorization header" });
    }

    // Set token for Clerk to parse
    const token = authHeader.split(" ")[1]; // Extract the actual token

    // Clerk middleware expects req.auth() to be available
    if (!req.auth) {
      return res.status(500).json({ success: false, message: "Clerk auth not initialized" });
    }

    const { userId, has } = await req.auth();

    const hasPremiumPlan = await has({ plan: "premium" });

    const user = await clerkClient.users.getUser(userId);

    if (!hasPremiumPlan && user.privateMetadata.free_usage) {
      req.free_usage = user.privateMetadata.free_usage;
    } else {
      await clerkClient.users.updateUserMetadata(userId, {
        privateMetadata: { free_usage: 0 },
      });
      req.free_usage = 0;
    }

    req.plan = hasPremiumPlan ? 'premium' : 'free';
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
};
