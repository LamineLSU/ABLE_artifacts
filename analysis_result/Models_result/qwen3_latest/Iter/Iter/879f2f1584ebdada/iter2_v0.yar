rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B }  // TEST EAX, JE + PUSH context
        $pattern1 = { 8B 45 FC E8 25 05 00 00 }  // MOV + CALL to 00B5667F
        $pattern2 = { 8B 4D F8 E8 74 FA FF FF }  // MOV + CALL to 00B55C17

    condition:
        any of them
}