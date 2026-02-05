rule 'Bypass_SANDBOX_CHECKS' includes
    // Bypass TEST EAX check by skipping subsequent code
    85 C0 0F 84 ?? ?? ?? ?? 8B 45 ??
    // Bypass OR value check at address CE with wildcarded offset
    E8 ?? ?? ?? ??
    // Adapting near jump displacement for bypass without altering functionality
    6A ?? 5A 8B CE E8 ?? ?? ?? ??