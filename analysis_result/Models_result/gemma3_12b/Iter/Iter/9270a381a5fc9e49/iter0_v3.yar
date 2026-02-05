rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5E 5D C3 9E 70 AC }  // Bypass CALL EAX - pop esi, pop ebp, ret, sahf, jo
        $pattern1 = { 52 5E 5D 8B 16 FF D2 } // Bypass CALL EDX - push edx, pop esi, pop ebp, mov edx, dword ptr [esi], call edx
        $pattern2 = { 9A 98 2A 85 34 16 0F CC } // Bypass INT3 - call far, int3

    condition:
        any of them
}