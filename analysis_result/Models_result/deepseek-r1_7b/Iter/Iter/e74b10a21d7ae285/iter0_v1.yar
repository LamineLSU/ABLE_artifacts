rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using three different paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 00 00 00 8B 45 ?? }  // TEST EAX JZ 0F84 + CALL
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 00 00 00 85 C0 0F 84 ?? ?? ?? ?? }  // E8C8FFFF + CALL with offset 5A
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  // PUSH, POP, MOV, CALL, TEST sequence

    condition:
        any of them
}