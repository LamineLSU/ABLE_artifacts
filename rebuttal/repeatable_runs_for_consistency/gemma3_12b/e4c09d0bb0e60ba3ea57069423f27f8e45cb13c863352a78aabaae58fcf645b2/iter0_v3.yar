rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Skip conditional jump
        $pattern1 = { 50 57 8B 45 ?? 53 6A 40 53 68 40 11 2C 00 33 C9 } //Bypass call dword ptr [002C61F8]
        $pattern2 = { 50 57 8B 45 ?? 53 6A 40 53 68 40 11 A7 00 33 C9 } //Bypass call dword ptr [00A761F8]

    condition:
        any of them
}