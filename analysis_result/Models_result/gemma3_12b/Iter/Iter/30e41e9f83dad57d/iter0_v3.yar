rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 44 24 14 72 14 } // MOV [eax], dword ptr [esp+14h], JC 0040CFA3h
        $pattern1 = { 8B 44 24 08 3B 44 24 10 76 08 } // MOV [esp+08h], dword ptr [esp+08h], CMP [eax], dword ptr [esp+10h], JBE 0040CF9Bh
        $pattern2 = { 6A 00 5A 8B CE E8 ?? ?? ?? ?? } // PUSH 00000000h, POP, MOV, CALL, TEST

    condition:
        any of them
}