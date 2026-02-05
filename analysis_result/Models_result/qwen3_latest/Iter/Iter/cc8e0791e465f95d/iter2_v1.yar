rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 54 24 10 8B 0D ?? ?? ?? ?? FF D6 } // mov edx, [ecx+80h], call edx
        $pattern1 = { 8B 54 24 18 8B 0D ?? ?? ?? ?? FF D6 } // mov edx, [ecx+48h], call edx
        $pattern2 = { 8B 42 2C 8B 0D ?? ?? ?? ?? FF D6 }   // mov eax, [edx+4Ch], call eax

    condition:
        any of them
}