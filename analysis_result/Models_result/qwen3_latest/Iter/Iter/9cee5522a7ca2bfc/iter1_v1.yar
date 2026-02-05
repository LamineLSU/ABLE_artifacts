rule ExitProcessCheck
{
    meta:
        description = "Pattern matching code that leads to ExitProcess"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    strings:
        $a = { 0F 84 ?? ?? ?? ?? }  // JZ instruction with 4-byte offset
        $b = { 85 C0 0F 84 ?? ?? ?? ?? }  // TEST EAX, EAX followed by JZ
        $c = { 8B 45 ?? 85 C0 0F 84 ?? ?? ?? ?? }  // MOV EAX, [ESP+?] + TEST + JZ
    condition:
        all of them
}