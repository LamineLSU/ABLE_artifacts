rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 81 FB 09 03 00 00 7D 07 }  //cmp ebx, 00000309h; jnl
        $pattern1 = { FF 15 44 75 EA 00 53 8D 85 94 FE FF FF FF } // CALL + PUSH + MOV
        $pattern2 = { 83 F6 56 56 56 68 0C 80 E9 00 }  //XOR esi, esi + PUSH

    condition:
        any of them
}