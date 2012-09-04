package ca.uqac.logic.vl;

import java.io.*;

import ca.uqac.net.rules.FirewallRuleList;

public class RuleChecker
{
  public static void main(String[] args)
  {
    long timeBeg = 0, timeEnd = 0;
    int verbosity = 1;
    
    // Read the rule base
    String fileContents = "";
    if (args.length == 0)
    {
      System.err.println("No input file specified");
      System.exit(1);
    }
    String fileName = args[0];
    if (args.length == 2 && args[1].compareTo("--quiet") == 0)
    {
      verbosity = 0;
    }
    try
    {
      fileContents = Utilities.readFileAsString(fileName);
    }
    catch (IOException e)
    {
      System.err.println("Error reading file");
      System.exit(1);
    }
    FirewallRuleList rl = new FirewallRuleList(fileContents);
    
    
    // Define operators for common anomalies
    Operator shadowing = createShadowing();
    Operator correlation = createCorrelation();
    Operator generalization = createGeneralization();
    Operator redundant = createRedundant();
    
    
    // Evaluate the rules
    timeBeg = System.nanoTime();
    for (int i = 0; i < rl.size(); i++)
    {
      if (shadowing.evaluate(rl, i))
      {
        if (verbosity > 0)
          System.out.println("Shadowing anomaly for rule " + i);
      }
      if (correlation.evaluate(rl, i))
      {
        if (verbosity > 0)
          System.out.println("Correlation anomaly for rule " + i);
      }
      if (generalization.evaluate(rl, i))
      {
        if (verbosity > 0)
          System.out.println("Generalization anomaly for rule " + i);
      }
      if (redundant.evaluate(rl, i))
      {
        if (verbosity > 0)
          System.out.println("Redundancy anomaly for rule " + i);
      }
    }
    timeEnd = System.nanoTime();
    /*if (verbosity > 0)
      System.out.println("No anomalies detected");*/
    System.err.println(timeEnd - timeBeg);
  }
  
  private static Operator createShadowing()
  {
    OperatorDiamond shadowing = new OperatorDiamond();
    shadowing.setForward(false);
    shadowing.setRelation(new Includes());
    shadowing.setOperator(new ConstantTrue());
    return shadowing;
  }
  
  private static Operator createCorrelation()
  {
    OperatorOr correlation = new OperatorOr();
    
    // Left member
    OperatorAnd leftor = new OperatorAnd();
    leftor.setLeft(new Accept());
    OperatorDiamond leftordiam = new OperatorDiamond();
    leftordiam.setRelation(new Intersect());
    leftordiam.setOperator(new Deny());
    leftor.setRight(leftordiam);
    correlation.setLeft(leftor);
    
    // Right member
    OperatorAnd rightor = new OperatorAnd();
    rightor.setLeft(new Deny());
    OperatorDiamond rightordiam = new OperatorDiamond();
    rightordiam.setRelation(new Intersect());
    rightordiam.setOperator(new Accept());
    rightor.setRight(leftordiam);
    correlation.setRight(rightor);

    return correlation;
  }
  
  private static Operator createGeneralization()
  {
    OperatorOr correlation = new OperatorOr();
    
    // Left member
    OperatorAnd leftor = new OperatorAnd();
    leftor.setLeft(new Accept());
    OperatorDiamond leftordiam = new OperatorDiamond();
    leftordiam.setRelation(new Included());
    leftordiam.setOperator(new Deny());
    leftor.setRight(leftordiam);
    correlation.setLeft(leftor);
    
    // Right member
    OperatorAnd rightor = new OperatorAnd();
    rightor.setLeft(new Deny());
    OperatorDiamond rightordiam = new OperatorDiamond();
    rightordiam.setRelation(new Included());
    rightordiam.setOperator(new Accept());
    rightor.setRight(leftordiam);
    correlation.setRight(rightor);

    return correlation;
  }
  
  private static Operator createRedundant()
  {
    OperatorOr correlation = new OperatorOr();
    
    // Left member
    OperatorAnd leftor = new OperatorAnd();
    leftor.setLeft(new Accept());
    OperatorDiamond leftordiam = new OperatorDiamond();
    leftordiam.setForward(false);
    leftordiam.setRelation(new Includes());
    leftordiam.setOperator(new Deny());
    leftor.setRight(leftordiam);
    correlation.setLeft(leftor);
    
    // Right member
    OperatorAnd rightor = new OperatorAnd();
    rightor.setLeft(new Deny());
    OperatorDiamond rightordiam = new OperatorDiamond();
    rightordiam.setForward(false);
    rightordiam.setRelation(new Includes());
    rightordiam.setOperator(new Accept());
    rightor.setRight(leftordiam);
    correlation.setRight(rightor);

    return correlation;
  }
}
