rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }  // Test EAX + JE + Push/Pop/Call sequence
        $pattern1 = { E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? }      // CALL + Test EAX + Conditional Jump
        $pattern2 = { A1 ?? ?? ?? ?? 85 C0 74 ?? FF 15 ?? ?? ?? ?? } // MOV EAX + Test EAX + JE + CALL ExitProcess

    condition:
        any of them
}