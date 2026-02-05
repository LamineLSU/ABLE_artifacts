rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B } // Test EAX + JE + PUSH 0x5B
        $pattern1 = { FF 15 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? } // Call [addr] + PUSH EBX + Call [addr]
        $pattern2 = { E8 C8 FF FF 59 FF 15 ?? ?? ?? ?? } // CALL + POP ECX + CALL [addr]

    condition:
        any of them
}