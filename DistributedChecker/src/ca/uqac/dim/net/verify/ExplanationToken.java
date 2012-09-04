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

/**
 * Base class representing any element that can contribute to the
 * explanation of an anomaly. Explanation tokens are aligned in
 * a vector to form an {@link ExplanationTrace}. This class is
 * abstract and is intended to be implemented with specific kinds
 * of explanations. 
 * @author sylvain
 *
 */
public abstract class ExplanationToken
{
  /**
   * The device on which the rule is processed
   */
  protected int m_deviceName;
  
}
