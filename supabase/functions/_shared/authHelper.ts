// Shared authentication helper for Supabase Edge Functions
// Extracts and validates the authenticated user from the Authorization Bearer JWT

export async function getAuthenticatedUser(
  req: Request,
  supabase: any
): Promise<{ id: string; email?: string } | null> {
  const authHeader = req.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  if (!token) return null;

  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) {
      return null;
    }
    return { id: data.user.id, email: data.user.email };
  } catch {
    return null;
  }
}
