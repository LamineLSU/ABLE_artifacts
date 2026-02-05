rule ExitProcessCall
{
    meta:
        description = "Detects the call to ExitProcess with surrounding context"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-01"
        type = "malware"
        tags = "exitprocess", "evasion", "anti-analysis"

    strings:
        $a = { 52 FF D0 5E 5D C3 } // push edx, call eax, pop esi, pop ebp, ret
        $b = { 8B 4D 0C 8B 46 ?? 83 C4 14 52 FF D0 } // mov edx, [ebp+0C], mov eax, [esi], add esp, push edx, call eax
        $c = { 8B 46 ?? 83 C4 14 52 FF D0 } // mov eax, [esi], add esp, push edx, call eax

    condition:
        (all of ($a) or all of ($b) or all of ($c))
}