rule Evasion_Bypass
{
    meta:
        description = "Bypasses evasion by skipping critical call setup and checks"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 52 8B 16 50 51 FF D2 } // push edx, mov edx, [esi], push eax, push ecx, call edx
        $b = { FF D2 5E 5D C3 }       // call edx, pop esi, pop ebp, ret
        $c = { 52 8B 16 50 }          // push edx, mov edx, [esi], push eax
    condition:
        $a or $b or $c
}