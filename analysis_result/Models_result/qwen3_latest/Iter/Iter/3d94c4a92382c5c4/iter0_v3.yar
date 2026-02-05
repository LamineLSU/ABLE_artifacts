rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 68 ?? ?? ?? ?? }  // ExitProcess call + preceding CreateThread setup
        $pattern1 = { FF 15 ?? ?? ?? ?? 85 C0 0F 85 ?? ?? ?? ?? 8B 4D FC }  // WaitForSingleObject + test eax + jne + mov ecx
        $pattern2 = { FF 15 ?? ?? ?? ?? 6A 00 50 FF D7 6A 00 50 FF D7 }         // CloseHandle calls + Sleep setup before exit

    condition:
        any of them
}