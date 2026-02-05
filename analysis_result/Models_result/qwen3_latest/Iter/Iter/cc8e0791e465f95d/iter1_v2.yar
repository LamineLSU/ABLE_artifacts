rule Sample_API_Calls
{
    meta:
        description = "Detects memory manipulation via API calls in the sample"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        confidence = 85

    strings:
        $a = { 8B 91 ?? ?? ?? ?? FF D2 }  // NtWriteVirtualMemory call
        $b = { 8B 91 A4 00 00 00 83 C2 08 52 FF D2 }  // WriteProcessMemory call
        $c = { 8B 45 D8 8B 42 4C FF D0 }  // SetThreadContext call

    condition:
        any of ($a, $b, $c)
}