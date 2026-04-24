rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 FF 15 ?? ?? ?? ?? 33 FF }  // ExitProcess call with push ebx and xor edi
        $pattern1 = { 85 C0 74 ?? ?? ?? ?? 6A 5B }  // Early EAX test + je + push 0x5B
        $pattern2 = { 50 FF 15 ?? ?? ?? ?? 53 }     // CloseHandle call with push eax and push ebx

    condition:
        any of them
}