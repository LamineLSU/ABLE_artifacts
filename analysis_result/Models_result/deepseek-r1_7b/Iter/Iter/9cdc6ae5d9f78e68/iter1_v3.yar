rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 01 2C FC 51 FF 75 08 DD EB 08 }
                  { [012CFC54] call dword ptr [012E30A8h] }

        $pattern1 = { 01 2C FC 4B E8 4E 00 00 00 CA 01 2C FC 9E }
                  { [012CFC50] 59 pop ecx }

        $pattern2 = { 01 2C FC 3B FF 15 40 30 2E 01 CA DD 01 2E 30 40 }
                  { [012CFC38] FF7508 push dword ptr [ebp+08h] }
                  { [012CFC36] 7510 jne ... }

    condition:
        any of the patterns matched
}