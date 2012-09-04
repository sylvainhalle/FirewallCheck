package ca.uqac.logic.vl;

import java.io.*;

public class Utilities
{
  /**
   * Read the contents of a file and puts it into a String
   * @param filePath
   * @return
   * @throws java.io.IOException
   */
  public static String readFileAsString(String filePath) throws java.io.IOException
  {
      StringBuffer fileData = new StringBuffer(1000);
      BufferedReader reader = new BufferedReader(new FileReader(filePath));
      char[] buf = new char[1024];
      int numRead=0;
      while((numRead=reader.read(buf)) != -1)
      {
          fileData.append(buf, 0, numRead);
      }
      reader.close();
      return fileData.toString();
  }
  
  /**
   * Puts the contents of a string into a file
   * @param filename The file to write to
   * @param contents The contents to write into the file
   */
  public static void writeStringAsFile(String filename, String contents) throws java.io.IOException
  {
	  BufferedWriter out = new BufferedWriter(new FileWriter(filename));
	  out.write(contents);
	  out.close();

  }
}
