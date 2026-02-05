rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 } // TEST EAX, JE (conditional check)
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? } // MOV ECX, ESI + CALL (function call)
        $pattern2 = { 03 C1 B9 42 8C 39 00 50 E8 ?? ?? ?? ?? } // ADD, MOV, PUSH, CALL (timing or control flow)

    condition:
        any of them
}