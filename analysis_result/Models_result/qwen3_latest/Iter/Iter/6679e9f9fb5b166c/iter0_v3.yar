rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 9C FD FF FF E8 D9 CE FF FF 89 85 11 00 00 00 }  // mov eax, [ebp-00000264h] + call 00403D98h + mov [ebp-00000118h], eax
        $pattern1 = { 33 C0 E8 A5 91 FE FF 8B 45 88 85 C0 74 ?? ?? ?? ?? }  // xor eax, eax + call 00402754h + test eax, eax + jz (context)
        $pattern2 = { 8D 45 8C E8 AD C2 FE FF 8B 45 88 85 C0 74 ?? ?? ?? ?? }  // lea eax, [ebp-0000027Ch] + call 00403D88h + test eax, eax + jz (context)

    condition:
        any of them
}