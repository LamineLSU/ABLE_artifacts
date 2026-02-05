rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 08 A9 C5 1E B6 55 } // mov eax, [ebp+8] followed by test eax, 55B61EC5h
        $pattern1 = { 55 8B 45 08 FF D2 55 8B } // push edx, mov edx, [ebp+8], call edx, push edx, mov ebp
        $pattern2 = { 8D 45 08 00 00 E8 74 0A 00 00 } // lea esi, [eax+0000], call 0041EC07h

    condition:
        any of them
}