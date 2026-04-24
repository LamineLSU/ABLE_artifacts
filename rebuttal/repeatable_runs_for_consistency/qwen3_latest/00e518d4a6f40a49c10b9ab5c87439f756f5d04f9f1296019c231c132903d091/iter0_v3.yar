rule ExitCheck
{
    meta:
        description = "Detects a call to ExitProcess with preceding checks"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2023-10-15"

    strings:
        $a = { 85 C0 74 ?? 6A ?? }  // First test and je followed by push
        $b = { 85 C0 0F 84 ?? ?? ?? ?? }  // Second test and je
        $c = { 85 C0 E8 ?? ?? ?? ?? }  // Test followed by call to ExitProcess

    condition:
        all of them
}