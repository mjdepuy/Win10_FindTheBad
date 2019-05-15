# Script for quickly looking for Win10 badness. This script will take primary
# advantage of PowerShell's capabilities and substitute with WMIC
# where necessary. 
#
# STILL TO DO:  Dump everything to individual files
#               Prefetch parsing
#               Chrome/FireFox extensions
#               IE/Edge/Chrome/FireFox history
#               Certificates (for all users)
#
# Author: Michael Depuy
# Date: 27 March 2019

$divider = "############################"

###########################################################
################## RECYCLE BIN FUNCTIONS ##################
###########################################################
# Returns SHA-1 hash of file < 50MB
function Get-ShaHash
{
    param($file,
        [int] $size)
    
    # If file size is greater than 50MB, skip hashing
    If ($size -gt 52428800){
        return "00000000000000000000000000000000"
    }
    Else{
        $sha = new-object -TypeName System.Security.Cryptography.SHA1CryptoServiceProvider
        $hash = [System.BitConverter]::ToString($sha.ComputeHash([System.IO.File]::ReadAllBytes($file)))
        return $hash -replace '-',''
    }
}

function Get-DeletedMetadata
{
    param($file)
    # Header
    # If header matches a $I file, go through parser
    #   Else, just print file name and type
    $header = Get-Content -Encoding Byte -path $file -totalcount 8
    $header_str = [System.BitConverter]::ToString($header) -replace '-'
    #Windows 10
    If ($header_str -match "0200000000000000"){
        $size = (Get-Content -Encoding Byte -path $file)[8 .. 15]
        $file_size = [System.BitConverter]::ToInt64($size,0)
        $temp_time = (Get-Content -Encoding Byte -path $file)[16 .. 23]
        $temp = [System.BitConverter]::ToInt64($temp_time,0)
        $del_time = [DateTime]::FromFileTime($temp)
        #Grab original file location
        $diff = (Get-Item $file).Length
        $orig_path = (Get-Content -Encoding Byte -path $file)[28 .. $diff]
        $path_str = [System.Text.Encoding]::Ascii.GetString($orig_path) -replace "\x00"
        $filename = (Get-Item $file).Name
        $mdhash = Get-MdHash -file $file -size $diff
        $shahash = Get-ShaHash -file $file -size $diff
        
        $filedata = " Filename=`""+[string]$filename+"`""+" Header=`""+[string]$header_str +"`"" +" Original_size=`""+[string]$file_size +"`"" +" Original_file_path=`""+[string]$path_str +"`"" +" Deleted_date=`""+[string]$del_time +"`"" + " File_Hash_SHA1=`""+ $shahash +"`"" 
                 
        Write-Host $filedata
    }

    # If the file header does not match an $I file, print name, header, size, location
    Else{
        $file_size = (Get-Item $file).Length
        $filename = (Get-Item $file).Name
        $path_str = (Get-Item $file).FullName
        $mdhash = Get-MdHash -file $file -size $file_size
        $shahash = Get-ShaHash -file $file -size $file_size
        
        $filedata = " Filename=`""+[string]$filename+"`""+" Original_size=`""+[string]$file_size +"`"" +" Original_file_path=`""+[string]$path_str +"`"" + " File_Hash_SHA1=`""+ $shahash +"`""
        
        Write-Host $filedata
    }
    
}

###########################################################
###################### DEVICE INFO ########################
###########################################################
# Get username and computer name
$user = Get-Content Env:username
$cname = Get-Content Env:computername

Write-Host "Starting analysis of $($cname) under user $($user).`n"
Write-Host "Testing for administrator rights...`n"

# Test for admin rights. To get the most out of the script, elevate to administrator.
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$is_admin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

If($is_admin -eq "True"){
    Write-Host "We have admin rights! Continuing as admin....`n"
}
Else{
    Write-Host "Not an administrator. To receive a more detailed report, please run as administrator."
    Write-Host "Continuing as a normal user...`n"
}

###########################################################
#################### NETWORK ANALYSIS #####################
###########################################################
Write-Host $divider
Write-Host "Grabbing network configuration information"
ipconfig /all

Write-Host $divider
Write-Host "Grabbing network connections"

If($is_admin -eq "True"){
    netstat -anob
}
Else{
    netstat -ano
}

###########################################################
#################### PROCESS ANALYSIS #####################
###########################################################

Write-Host $divider
Write-Host "Grabbing process list"
Get-Process

Write-Host $divider
Write-Host "Grabbing services list"
Get-Service

Write-Host $divider
Write-Host "Grabbing modules list (this takes a while)"
Get-process -Module

###########################################################
################ RECYCLE BIN ANALYSIS #####################
###########################################################
Write-Host $divider
Write-Host "Starting Recycle Bin analysis"
$ErrorActionPreference = "silentlycontinue"
$WIN10IHEADERSTR = "0200000000000000"
$path = 'C' + ':\$Recycle.Bin'
$bin = Get-ChildItem $Path  -Force -Recurse

foreach ($item in $bin){
    $tempr=$item.Attributes
    if ($item.Attributes -notmatch "Directory"){    
        If ($item.Name -match "desktop.ini"){
            continue
        }
        Else{
            $f = $item.FullName
            Get-DeletedMetadata -file $f
        }
    }
    Write-Host 
}

###########################################################
#################### REGISTRY ANALYSIS ####################
###########################################################
Write-Host $divider
Write-Host "`nBeginning registry analysis"
Write-Host "`n-------Getting registry autoruns-------`n"
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\Currentversion\Run
Get-ItemProperty -Path HKLM:\Software\Microsoft\Windows\Currentversion\RunOnce
Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Currentversion\Run
Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Currentversion\RunOnce

Write-Host "`n-------Getting userinit-------`n"
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components

Write-Host "`n-------Getting process MRU-------`n"
$pidmru = Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
$pidmru
ForEach($p in $pidmru.Property){
    $prop = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU -Name $p
    Write-Host "`n$($prop)"
    [System.Text.Encoding]::Ascii.GetString($prop.$p)
    Write-Host "`n"
}

Write-Host $divider
Write-Host "`n-------Getting RunMRU-------`n"
Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU


Write-Host $divider
Write-Host "`n-------Getting file MRU-------`n"
$filemru = Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
$filemru
ForEach($p in $filemru.Property){
    $prop = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs -Name $p
    Write-Host "`n$($prop)"
    [System.Text.Encoding]::Ascii.GetString($prop.$p)
    Write-Host "`n"
}

###########################################################
#################### LNK FILE ANALYSIS ####################
###########################################################
Write-Host $divider
Write-Host "`nBeginning LNK file analysis"
$windows_recent_path = "C:\Users\$($user)\AppData\Roaming\Microsoft\Windows\Recent"
$office_recent_path = "C:\Users\$($user)\AppData\Roaming\Microsoft\Office\Recent"
# First LNK path
$lnk_windows = Get-ChildItem $windows_recent_path | sort LastWriteTime -Descending
ForEach($f in $lnk_windows){
    Write-Host "$($f.Name) `t $($f.LastWriteTime)"
}

###########################################################
#################### PREFETCH ANALYSIS ####################
###########################################################
Write-Host $divider
Write-Host "`nBeginning prefetch analysis."
$pf_exists = Test-Path "C:\Windows\Prefetch"
If($pf_exists -eq $false){
    Write-Host "`nNo prefetch directory detected. Continuing..."
}
Else{
    If($is_admin -eq $false){
        Write-Host "`nAdmin rights not detected. Continuing..."
    }
    Else{
        $pf = Get-ChildItem C:\Windows\Prefetch | sort LastWriteTime -Descending
        ForEach($f in $pf){
            Write-Host "$($f.Name) `t $($f.LastWriteTime)"
        }
    }
}



Write-Host "`n$($divider)"
Write-Host "Fin."
