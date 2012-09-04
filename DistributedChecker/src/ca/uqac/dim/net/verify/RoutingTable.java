/*-------------------------------------------------------------------------
    Distributed Firewall Anomaly Detector
    Copyright (C) 2012  Sylvain Hallé

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 -------------------------------------------------------------------------*/
package ca.uqac.dim.net.verify;

import java.util.*;

public class RoutingTable extends Vector<RoutingRule>
{

  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  
  public RoutingTable()
  {
    super();
  }
  
  /**
   * Parse a routing table from a multi-line string
   * @param s
   */
  public RoutingTable(String s)
  {
    this();
    String[] lines = s.split("[\r\n]");
    for (String li : lines)
    {
      li = li.trim();
      if (li.isEmpty())
        continue;
      if (li.startsWith("#"))
        continue;
      RoutingRule r = new RoutingRule(li);
      this.add(r);
    }
  }
  
  @Override
  public String toString()
  {
    StringBuilder out = new StringBuilder();
    for (RoutingRule r : this)
    {
      out.append(r).append("\n");
    }
    return out.toString();
  }

}
