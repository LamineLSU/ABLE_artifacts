rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Push 0x5B, Pop EDX, MOV ECX, ESI, Call, Test
        $pattern1 = { 68 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? A1 ?? ?? ?? ?? } // Push Address, XOR, Call, Mov
        $pattern2 = { FF 15 ?? ?? ?? ?? 53 6A 40 53 68 ?? ?? ?? ?? } // Call, Push, Push, Push, Push

    condition:
        any of them
}