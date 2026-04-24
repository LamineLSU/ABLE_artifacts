rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 52 8B 16 50 51 FF D2 }  // CALL+PUSH+MOV+CALL sequence
        $pattern1 = { 77 B8 0A 04 B6 6F C1 84 81 6A 00 55 8B EC }   // JNBE+OR+OUTSD+ROL combo
        $pattern2 = { 8D B0 74 0C 00 00 56 50 E8 44 09 00 00 }     // LEA+PUSH+CALL pattern

    condition:
        any of them
}