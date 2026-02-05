rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3C 22 75 28 41 8A 11 84 D2 74 11 }  // cmp al,22h + jne + inc ecx + mov dl + test dl + je
        $pattern1 = { 80 FA 22 0F 45 C1 8B C8 EB 0E }      // cmp dl,22h + cmovne + mov ecx + jmp
        $pattern2 = { 3C 20 7F F9 EB 07 }              // cmp al,20h + jnle + jmp

    condition:
        any of them
}