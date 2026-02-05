rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5E 36 ?? ?? ?? ?? ??
                      8B 45 0C F2 FF FF FF 00 85 C0 }
        $pattern1 = { 6A 36 ?? ?? ?? ?? ??
                      8B 45 F9 FF FF FF FF 00 8B 55 0C }
        $pattern2 = { 6A 1E ?? ?? ?? ?? ??
                      8B 45 F9 FF FF FF FF 00 8B 55 0C }
}

# Example of how to use the patterns in yara (adjust based on your system's architecture)
# Note: The patterns should be wrapped in { } and adjusted for specific instruction lengths
# This is a simplified example; adjust as needed.

# Example rule using pattern0:
rule Bypass_Evasion_0 {
    meta:
        description = "Bypasses return address check after call with large offset"
        cape_options = "count=1"

    includes: $pattern0
    condition: any
}

# Similarly, create rules for pattern1 and pattern2