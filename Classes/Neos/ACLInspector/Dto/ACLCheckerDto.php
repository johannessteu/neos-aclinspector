<?php
namespace Neos\ACLInspector\Dto;


class ACLCheckerDto
{

    /**
     * @var string
     */
    protected $startOnNodePath;

    /**
     * @var string
     */
    protected $stopOnNodePath;

    /**
     * @var array
     */
    protected $roles = [];

    /**
     * @return array
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @param array $roles
     */
    public function setRoles($roles)
    {
        $this->roles = $roles;
    }

    /**
     * @return string
     */
    public function getStartOnNodePath()
    {
        return $this->startOnNodePath;
    }

    /**
     * @param string $startOnNodePath
     */
    public function setStartOnNodePath($startOnNodePath)
    {
        $this->startOnNodePath = $startOnNodePath;
    }

    /**
     * @return string
     */
    public function getStopOnNodePath()
    {
        return $this->stopOnNodePath;
    }

    /**
     * @param string $stopOnNodePath
     */
    public function setStopOnNodePath($stopOnNodePath)
    {
        $this->stopOnNodePath = $stopOnNodePath;
    }


}