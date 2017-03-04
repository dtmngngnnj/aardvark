package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// tl;dr : extract a number of (text) files but only update the files if the content is different.
// If an aardvark.sh script is produced (well, exists) it is executed at the end.
//
// TODO: develop assemble functionality

const (
	prologue          = "AARDVARK:"
	defaultPattern    = "##=="          // default pattern to split on
	executeScript     = "./aardvark.sh" // including path
	executeScriptName = "aardvark.sh"   // filename only
	trace             = false           // for debugging purposes
)

var globalAardvarkshHash [20]byte

func main() {

	pattern, filename, showHelpAndQuit, assemble, compose := digestArgs()

	// step 0: if digesting of args went wrong, then just show help and quit
	if showHelpAndQuit {
		showHelp()
		return
	} else if compose {
		// compose an aardvark file from a number of files
		// eg. aardvark -c geoip/info.txt ./readtext/pg2600_war_and_peace.txt > aardvark.code
		composeFromFiles()
		return
	} else if assemble {
		// TODO
		// other way round: instead of reading the file-content from
		// aardvark.code, read the files from disk, and assemble aardvark.code
		// 1. backup original aardvark to aardvark_1.code
		// 2. read the files mentioned in bu-filename ('aardvark_1.code')
		// 3. write to 'aardvark.code'
		fmt.Println("Assemble not yet implemented.")
		return
	}

	splitAndExecute(pattern, filename)
}

// the core aardvark functionality
func splitAndExecute(pattern []byte, filename string) {

	// step 1: digest and split the content PASS 1: only read and store the tags
	// (this is to ensure all tags are stored in the tagdict and can be referenced
	//  while only defined later on in the aardvark.code file)
	tagdict := make(map[string][]byte)
	ok := splitContent(pattern, filename, tagdict, true)

	// step 2: digest and split the content PASS 2: also write the files
	ok = splitContent(pattern, filename, tagdict, false)

	// step 3: execute the aardvark.sh script
	if ok {
		execAardvarkShScript() // check return value?
	}
	fmt.Println()
}

// split the content into files, storing tags in the tagdict,
// or filling in the tags from the tagdict
// when noFileWrite == true, no files are written, only the tags are written/stored
func splitContent(pattern []byte, filename string, tagdict map[string][]byte, noFileWrite bool) bool {
	if trace {
		fmt.Println("TRACE: splitContent()")
	}
	chunkfilename := ""
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%s %v\n", prologue, err) // cannot open file
		return false
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 4096)

	containsTagsFlag := false
	lineCounter := 0
	var content bytes.Buffer
	for {
		linebyte, isPrefix, err := r.ReadLine()
		lineCounter += 1

		if err != nil {
			break
		}
		if isPrefix {
			fmt.Printf("Buffer too small.\n", prologue)
			break
		}
		if len(linebyte) == 0 {
			content.Write([]byte("\n"))
			continue
		}
		isContent := true

		if i := bytes.Index(linebyte, pattern); i == 0 {
			if ignore(linebyte[len(pattern):]) { // eg separator line
				continue
			}
			// write to file or store in dict[tag], the lines we have collected up to now.
			if len(chunkfilename) > 0 {
				writeFile(chunkfilename, content.Bytes(), tagdict, containsTagsFlag, noFileWrite)
				containsTagsFlag = false
			}
			content.Reset() // empty the old content

			// get the chunkfilename after the split-pattern: it's either a filename or a tag
			chunkfilename = strings.TrimLeft(string(linebyte[(i+len(pattern)):]), " ")
			i = strings.Index(chunkfilename, " ") // strip everything after the first space after the chunkfilename
			if i >= 0 {
				chunkfilename = chunkfilename[0:i]
			}
			if trace {
				fmt.Printf("TRACE: file:[%s]\n", chunkfilename)
			}
			isContent = false
		} else {
			// [[$ tag ]] will pull in the tag stored in the tagdict
			if !containsTagsFlag {
				if i := bytes.Index(linebyte, []byte("[[$")); i >= 0 {
					if j := bytes.Index(linebyte, []byte("]]")); j > i {
						containsTagsFlag = true
						isContent = true
					}
				}
			}
		}
		if isContent {
			content.Write(linebyte)
			content.Write([]byte("\n"))
		}
	}
	if (err != io.EOF) && (err != nil) {
		fmt.Printf("%s Error: %v\n", prologue, err)
	}
	if (len(chunkfilename) > 0) && (content.Len() > 0) {
		writeFile(chunkfilename, content.Bytes(), tagdict, containsTagsFlag, noFileWrite)
	}

	if trace {
		fmt.Printf("TRACE: Read %d lines\n", lineCounter)
		for key, value := range tagdict {
			fmt.Printf("TRACE [k]->[v]: [%v] -> [%v]\n", key, string(value))
		}
	}
	return true
}

func execAardvarkShScript() bool {
	// does the script exist?
	stat, err := os.Stat(executeScript)
	if os.IsNotExist(err) {
		fmt.Printf("%s Script '%s' doesn't exist.", prologue, executeScript)
		return false
	}

	// so the script exists, let's calc its hash
	scriptcontent, err := ioutil.ReadFile(executeScript)
	if err != nil {
		fmt.Printf("%s Script '%s' does NOT exist.", prologue, executeScript)
	}
	fileAardvarkshHash := sha1.Sum(scriptcontent)

	// if it is not the same as what's in the current .code file, return
	if fileAardvarkshHash != globalAardvarkshHash {
		fmt.Printf("%s Script '%s' differs, not executing.", prologue, executeScript)
		return false
	}

	// if it is not executable, make it executable...
	if (stat.Mode() & 0111) == 0 {
		if trace {
			fmt.Printf("TRACE: Script has mode '%d', chmodding.", stat.Mode()&0111)
		}
		os.Chmod(executeScript, 0755)
	}

	// execute, connecting output to stdout and stderr
	cmd := exec.Command(executeScript)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		fmt.Printf("%s ERROR: %v\n", prologue, err)
		return false
	}
	return true
}

// Write the content to a file OR store it in tagdict.
// The file will not be written if the content hasn't changed.
func writeFile(filename string, content []byte, tagdict map[string][]byte,
	containsTagsFlag bool, noFileWrite bool) {
	if trace {
		fmt.Printf("TRACE: Handling %s, containsTagsFlag=%v noFileWrite=%v\n",
			filename, containsTagsFlag, noFileWrite)
	}
	if len(filename) == 0 {
		fmt.Printf("%s WARNING: No filename given, nothing written!\n", prologue)
		return
	}

	// if it is a tag, store it in the tagdict
	if strings.Index(filename, "$") == 0 {
		// store as tag
		contentCopy := make([]byte, len(content), len(content))
		copy(contentCopy, content)
		tagdict[filename] = bytes.TrimRight(contentCopy, "\n")
		return
	}

	if noFileWrite {
		return
	}

	if containsTagsFlag {
		content = []byte(replaceTags(content, tagdict, 0))
	}

	// housekeeping: if we are looking at 'aardvark.sh', then store the hash
	// in a global var
	if strings.HasSuffix(filename, executeScriptName) {
		globalAardvarkshHash = sha1.Sum(content)
	}

	writereason := ""
	// read the 'old' content from file
	oldcontent, err := ioutil.ReadFile(filename)
	if err != nil {
		writereason = "..." // "file didn't exist yet" would be too obvious
	}

	// check: 1 compare the length of the old and new content
	if len(writereason) == 0 {
		if len(oldcontent) != len(content) {
			writereason = "content length differs."
		}
	}

	// check 2: compare the hash
	if len(writereason) == 0 {
		// calcuate the new hash
		oldHash := sha1.Sum(oldcontent)
		newHash := sha1.Sum(content)
		if oldHash != newHash {
			writereason = "content hash differs."
		}
	}

	if len(writereason) != 0 {
		fmt.Printf("%s writing %q, %s\n", prologue, filename, writereason)
		err = ensureParentDirectoryExists(filename)
		if err != nil {
			fmt.Println("Error creating parent directory: %v", err)
			return
		}
		ioutil.WriteFile(filename, []byte(content), 0644)
	}

}

func replaceTags(in []byte, tagdict map[string][]byte, recurseCounter int) []byte {
	if recurseCounter > 1000 {
		fmt.Fprintf(os.Stderr, "ERROR: Maximum recursion depth exceeded due to circular referencing!\n")
		os.Exit(1)
	}
	var out bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(in))
	//first := true
	sep := ""
	for scanner.Scan() {
		out.WriteString(sep)
		//fmt.Printf("\n---\n%s---\n", scanner.Text())
		txt := scanner.Bytes()
		for {
			start := bytes.Index(txt, []byte("[[$"))
			end := bytes.Index(txt, []byte("]]"))
			if start >= 0 && end > 0 && end > start {
				tag := strings.TrimSpace(string(txt[start+2 : end]))
				out.Write(txt[:start])
				out.Write(replaceTags(tagdict[tag], tagdict, recurseCounter+1))
				txt = txt[end+2:]
			} else {
				out.Write(txt)
				break
			}
		}
		//first = false
		sep = "\n"
	}
	return out.Bytes()
}

// digest the args passed on the command line, see further for more detail
func digestArgs() (pattern []byte, filename string, showHelpAndQuit bool, assemble bool, compose bool) {
	pattern = []byte(defaultPattern)
	showHelpAndQuit = false
	filename = "aardvark.code" // default input file

	lenArgs := len(os.Args)
	if lenArgs < 2 {
		// does the default file (aardvark.code) exist?
		_, err := os.Stat(filename)
		showHelpAndQuit = os.IsNotExist(err)
		return
	}
	if lenArgs > 3 {
		if os.Args[1] == "-c" {
			compose = true
		} else {
			showHelpAndQuit = true
		}
		return
	}
	if lenArgs == 3 {
		if os.Args[1] == "-c" {
			compose = true
		} else {
			pattern = []byte(os.Args[1])
			filename = os.Args[2]
		}
		return
	}
	if lenArgs == 2 {
		filename = os.Args[1]
		// first check some exceptions
		if filename == "-h" {
			showHelpAndQuit = true
		} else if filename == "-a" {
			assemble = true
		}
	}
	return
} /*
cases for which digestArgs returns true (in var 'showHelpAndQuit') :
- no args, and default code file (filename='aardvark.code') exists
- 1 arg: filename (ie. when differing from deftault 'aardvark.code')
- 2 args: pattern filename

cases for which digestArgs returns false:
- no args and 'aardvark.code' doesn't exist
- 1 arg: '-h'
- more than 2 args
*/

// Check that the parent directories for this file exist,
// if not then create them.
func ensureParentDirectoryExists(filename string) (err error) {
	if len(filename) == 0 {
		return
	}
	n := strings.LastIndex(filename, "/")
	if n < 0 {
		return // no slash, so it must be current dir, nothing to do
	}
	if filename[:n-1] == "." {
		return // current dir needs no creating
	}
	if _, err := os.Stat(filename[:n]); os.IsNotExist(err) {
		// create the directory
		err = os.MkdirAll(filename[:n], 0777)
	}
	return
}

// A line is ignorable when it only contains the same character (eg dash)
// repeated a number of times. Any spaces are ignored.
// eg. -----------------------------
func ignore(linebyte []byte) bool {
	var b byte = 0
	for _, v := range linebyte {
		if v == 32 {
			continue
		}
		if b == 0 {
			b = v
		} else {
			if b != v {
				return false
			}
		}
	}
	return true
}

// Create an aardvark.code file out of a number of files.
// Usage: aardvark -c geoip/info.txt ./readtext/pg2600_war_and_peace.txt > aardvark.code
func composeFromFiles() {
	start_index := 2

	// first check if all files exist
	bail_out := false
	for i, filename := range os.Args {
		if i >= start_index {
			if _, err := os.Stat(filename); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "File doesn't exist %s\n", filename)
				bail_out = true
			}
		}
	}
	if bail_out {
		fmt.Fprintf(os.Stderr, "(compose aborted)\n")
		return
	}

	// check passed, so let's do it
	sepline := "=============================================================================="
	for i, filename := range os.Args {
		if i >= start_index {
			numsepchars := 75 - len(filename)
			if numsepchars < 2 {
				numsepchars = 2
			}
			fmt.Printf("##== %s %s\n", filename, sepline[0:numsepchars])
			fd, err := os.Open(filename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Couldn't open file %s (%v)\n", filename, err) // cannot open file
			} else {
				if fd == nil {
					fmt.Fprintf(os.Stderr, "File descriptor nil for %s\n", filename) // cannot open file
				} else {
					io.Copy(os.Stdout, fd) // simply copy file to stdout
				}
			}
			fmt.Println()
		}
	}
}

func showHelp() {
	fmt.Printf(`
Usage: aardvark 
   or: aardvark -h
   or: aardvark <filename>
   or: aardvark <pattern> <filename>
   or: aardvark -c <filename1> <filename2> <filename3> .. > aardvark.code

The 'filename' is that of a file containing the content to be split, 
if no argument is given it's assumed to be 'aardvark.code' 

The 'pattern' is the pattern to split files on. 
- it should start at the beginning of a line
- it should be followed by the filename. 
- the filename should not contain any spaces
- the default pattern is '%s' 
- if a filename starts with a $-sign (eg $key), it is a tag, and the content 
  will not be written to a file but put in a dictionary. 
  Any subsequent file-entry can pull in the value stored under that $key 
  by putting [[$key]] by itself on a line. See examples. 

If after splitting the content, a file called 'aardvark.sh' exists, 
it will be executed.

On a second (and other) runs, the existing files are only overwritten 
if the content of that file in the 'aardvark.code' file has changed. 

The -c option is to compose an aardvark.code file from a number of existing files. 
    `, defaultPattern)
	fmt.Println()
}
