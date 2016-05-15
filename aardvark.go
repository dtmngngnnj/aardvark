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
	prologue       = "AARDVARK:"
	defaultPattern = "##--" // default pattern to split on
	executeScript  = "./aardvark.sh"
	trace          = false // for debugging purposes
)

func main() {

	pattern, filename, showHelpAndQuit, assemble := digestArgs()

	// step 0: if digesting of args went wrong, then just show help and quit
	if showHelpAndQuit {
		showHelp()
		return
	}

	if assemble {
		// TODO
		// other way round: instead of reading the file-content from
		// aardvark.code, read the files from disk, and assemble aardvark.code
		// 1. backup original aardvark to aardvark_1.code
		// 2. read the files mentioned in bu-filename ('aardvark_1.code')
		// 3. write to 'aardvark.code'
		fmt.Println("Assemble not yet implemented.")
	}

	splitAndExecute(pattern, filename)
}

// the core aardvark functionality
func splitAndExecute(pattern []byte, filename string) {

	// step 1: split the content (updating the files only if needed)
	ok := splitContent(pattern, filename)

	// step 2: execute the aardvark.sh script
	if ok {
		execAardvarkShScript() // check return value?
	}
	fmt.Println()
}

// split the content into files, storing tags in the tagdict,
// or filling in the tags from the tagdict
func splitContent(pattern []byte, filename string) bool {
	if trace {
		fmt.Println("TRACE: splitContent()")
	}
	tagdict := make(map[string][]byte)
	chunkfilename := ""
	f, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%s %v\n", prologue, err) // cannot open file
		return false
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 4096)

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
				writeFile(chunkfilename, content.Bytes(), tagdict)
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
			// <<# tag >> will pull in the tag stored in the tagdict
			if i := bytes.Index(linebyte, []byte("<<#")); i == 0 {
				if j := bytes.Index(linebyte, []byte(">>")); j > i {
					tag := strings.TrimLeft(string(linebyte[2:j]), " ")
					val, ok := tagdict[tag]
					if ok {
						content.Write(val)
						isContent = false
					} else {
						isContent = true
					}
					/*if trace {
						fmt.Printf("TAG:[%s] : %s\n", tag, string(tagdict[tag]))
					}*/
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
		writeFile(chunkfilename, content.Bytes(), tagdict)
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
// The file will not be written if the content is hasn't changed.
func writeFile(filename string, content []byte, tagdict map[string][]byte) {
	if trace {
		fmt.Printf("TRACE: Handling %s\n", filename)
	}
	if len(filename) == 0 {
		fmt.Printf("%s WARNING: No filename given, nothing written!\n", prologue)
		return
	}

	if strings.Index(filename, "#") == 0 {
		// store as tag
		contentCopy := make([]byte, len(content), len(content))
		copy(contentCopy, content)
		tagdict[filename] = contentCopy
		return
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
	} else {
		fmt.Printf("%s %q untouched.\n", prologue, filename)
	}
}

// digest the args passed on the command line, see further for more detail
func digestArgs() (pattern []byte, filename string, showHelpAndQuit bool, assemble bool) {
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
		showHelpAndQuit = true
		return
	}
	if lenArgs == 3 {
		pattern = []byte(os.Args[1])
		filename = os.Args[2]
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

func showHelp() {
	fmt.Printf(`
Usage: aardvark 
   or: aardvark -h
   or: aardvark <filename>
   or: aardvark <pattern> <filename>

The 'filename' is that of a file containing the content to be split, 
if no argument is given it's assumed to be 'aardvark.code' 

The 'pattern' is the pattern to split files on. 
- it should start at the beginning of a line
- it should be followed by the filename. 
- the filename should not contain any spaces
- the default pattern is '%s' 
- if a filename starts with a #-sign (eg #key), it is a tag, and the content 
  will not be written to a file but put in a dictionary. 
  Any subsequent file-entry can pull in the value stored under that #key 
  by putting <<#key>> by itself on a line. See examples. 

If after splitting the content, a file called 'aardvark.sh' exists, 
it will be executed.

On a second (and other) runs, the existing files are only overwritten 
if the content of that file in the 'aardvark.code' file has changed. 
    `, defaultPattern)
	fmt.Println()
}
