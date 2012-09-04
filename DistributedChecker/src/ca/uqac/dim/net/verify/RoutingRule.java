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

import ca.uqac.net.rules.*;

/**
 * A firewall rule is a rule whose decision is an integer,
 * standing for the next hop.
 * @author sylvain
 *
 */
public class RoutingRule extends Rule<Integer>
{
  public RoutingRule(String s)
  {
    super();
    String fields[] = s.split("[:|;|,|\\-|\\|]");
    m_fieldBegs.put("Destination", new Integer(fields[0].trim()).intValue());
    m_fieldEnds.put("Destination", new Integer(fields[1].trim()).intValue());
    // We ignore ports at the moment
    m_decision = new Integer(fields[2].trim()).intValue();
  }
  
  public String toString()
  {
    StringBuffer sb = new StringBuffer();
    sb.append(m_fieldBegs.get("Destination")).append(", ").append(m_fieldEnds.get("Destination")).append(", ");
    sb.append(m_decision);
    return sb.toString();
  }  
  
  public RoutingRule(int left, int right, int destination)
  {
    super();
    m_fieldBegs.put("Destination", left);
    m_fieldEnds.put("Destination", right);
    m_decision = destination;
  }
}
