rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }  //CALL instruction - Likely a timing check
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } //TEST + JZ - Conditional jump
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  //CALL + POP + MOV + CALL + TEST - Environment check

    condition:
        any of them
}