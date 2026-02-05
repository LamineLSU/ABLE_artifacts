rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Test EAX + JZ + MOV - 12 bytes
        $pattern1 = { E8 0B 00 00 00 59 FF 75 08 } // Call + Pop + Push - 10 bytes
        $pattern2 = { E8 C8 FF FF FF 59 FF 75 08 } // Call + Pop + Push - 10 bytes

    condition:
        any of them
}