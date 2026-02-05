rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 66 81 3C 24 E4 07 73 07 }  // cmp word ptr [esp], 07E4h; jnc 0046A0C7h
        $pattern1 = { E8 D1 C7 F9 FF } // call 00406898h
        $pattern2 = { 0F 94 C0 8B D8 }  //sete al; mov ebx, eax

    condition:
        any of them
}